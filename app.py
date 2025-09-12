import os
from urllib.parse import quote_plus
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from sqlalchemy import create_engine, Column, Integer, String, Date, ForeignKey, Table, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
import bcrypt
import re
import secrets
import datetime
from smtplib import SMTPException

# ============================================
# BANCO DE DADOS (somente DB_*; sem DATABASE_URL)
# ============================================

def build_db_url_from_parts() -> str:
    required = ["DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        raise RuntimeError(
            "Variáveis de banco ausentes: "
            + ", ".join(missing)
            + ". Defina DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME e (opcional) DB_SSL=true."
        )

    db_host = os.getenv("DB_HOST")
    db_port = int(os.getenv("DB_PORT"))
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME")
    db_ssl  = os.getenv("DB_SSL", "false").lower() == "true"

    # URL-encode na senha (trata @ ? : # & / etc.)
    db_pass_enc = quote_plus(db_pass)

    qs = "charset=utf8mb4"
    if db_ssl or "aivencloud.com" in (db_host or ""):
        qs += "&ssl=true"

    return f"mysql+pymysql://{db_user}:{db_pass_enc}@{db_host}:{db_port}/{db_name}?{qs}"

DATABASE_URL = build_db_url_from_parts()

_use_ssl = (
    "ssl=true" in DATABASE_URL
    or "aivencloud.com" in DATABASE_URL
    or os.getenv("DB_SSL", "false").lower() == "true"
)

engine = create_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_recycle=280,
    connect_args={'ssl': {}} if _use_ssl else {}
)

Session = sessionmaker(bind=engine)
Base = declarative_base()

# ============================================
# MODELOS
# ============================================

reuniao_participantes = Table(
    'reuniao_participantes', Base.metadata,
    Column('usuario_id', Integer, ForeignKey('usuarios.id'), primary_key=True),
    Column('reuniao_id', Integer, ForeignKey('reunioes.id'), primary_key=True)
)

TIPO_SINDICO = 0
TIPO_PENDENTE = 1
TIPO_MORADOR = 2

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    tipo = Column(Integer, default=TIPO_PENDENTE)
    condominio_id = Column(Integer, ForeignKey("condominio.id"), nullable=True)
    verification_code = Column(String(10), nullable=True)
    is_ativo = Column(Boolean, default=True, nullable=False)

    condominio = relationship("Condominio", back_populates="usuarios")
    reunioes = relationship("Reuniao", secondary=reuniao_participantes, back_populates="participantes")

    def is_authenticated(self): return True
    def is_active(self): return self.is_ativo
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

class Comunicado(Base):
    __tablename__ = "comunicados"
    id = Column(Integer, primary_key=True)
    titulo = Column(String(255), nullable=False)
    conteudo = Column(String(1000), nullable=False)
    data_postagem = Column(DateTime, default=datetime.datetime.utcnow)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=False)
    condominio_id = Column(Integer, ForeignKey("condominio.id"), nullable=False)

    usuario = relationship("Usuario", back_populates="comunicados")
    condominio = relationship("Condominio", back_populates="comunicados")

class Condominio(Base):
    __tablename__ = "condominio"
    id = Column(Integer, primary_key=True)
    nome = Column(String(150), nullable=False)
    endereco = Column(String(255), nullable=False)
    cnpj = Column(String(18), unique=True, nullable=True)
    telefone = Column(String(20), nullable=True)
    email = Column(String(100), nullable=True)
    data_cadastro = Column(Date, default=datetime.date.today)
    status = Column(String(50), default="pendente")
    usuarios = relationship("Usuario", back_populates="condominio")
    despesas = relationship("Despesa", back_populates="condominio")
    reunioes = relationship("Reuniao", back_populates="condominio")
    comunicados = relationship("Comunicado", back_populates="condominio")

class Despesa(Base):
    __tablename__ = "despesas"
    id = Column(Integer, primary_key=True)
    descricao = Column(String(255), nullable=False)
    valor = Column(Integer, nullable=False)
    data = Column(Date, nullable=False)
    categoria = Column(String(50), nullable=False)
    condominio_id = Column(Integer, ForeignKey("condominio.id"))
    condominio = relationship("Condominio", back_populates="despesas")

class Reuniao(Base):
    __tablename__ = "reunioes"
    id = Column(Integer, primary_key=True)
    titulo = Column(String(150), nullable=False)
    data = Column(Date, nullable=False)
    local = Column(String(255), nullable=False)
    condominio_id = Column(Integer, ForeignKey("condominio.id"))
    condominio = relationship("Condominio", back_populates="reunioes")
    participantes = relationship("Usuario", secondary=reuniao_participantes, back_populates="reunioes")

# Garantir tabelas no boot
try:
    with engine.begin() as conn:
        Base.metadata.create_all(bind=conn)
    print("Tabelas garantidas (create_all).")
except Exception as e:
    print("Falha ao criar tabelas no boot:", e)

# ============================================
# FLASK
# ============================================

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "troque_esta_chave_por_uma_muito_secreta")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    session_db = Session()
    try:
        return session_db.query(Usuario).get(int(user_id))
    finally:
        session_db.close()

# ============================================
# E-MAIL (SendGrid via SMTP)
# ============================================

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.sendgrid.net')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'apikey')   # SendGrid: SEMPRE "apikey"
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')              # API key SG.xxxxx
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  # remetente verificado

mail = Mail(app)

def send_email(subject: str, recipients: list[str], body: str, html: str | None = None) -> bool:
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD') or not app.config.get('MAIL_DEFAULT_SENDER'):
        app.logger.error('Config SMTP incompleta: verifique MAIL_USERNAME/MAIL_PASSWORD/MAIL_DEFAULT_SENDER.')
        return False
    try:
        msg = Message(subject=subject, recipients=recipients)
        msg.body = body
        if html:
            msg.html = html
        mail.send(msg)
        return True
    except SMTPException as e:
        app.logger.exception(f'Falha ao enviar e-mail (SMTPException): {e}')
        return False
    except Exception as e:
        app.logger.exception(f'Erro inesperado ao enviar e-mail: {e}')
        return False

# ============================================
# HELPERS
# ============================================

def requer_sindico(usuario_ativo):
    if not usuario_ativo or usuario_ativo.tipo != TIPO_SINDICO:
        abort(403)

# ============================================
# ROTAS
# ============================================

@app.route('/comunicados', methods=['GET', 'POST'])
@login_required
def comunicados():
    if current_user.tipo != TIPO_SINDICO:
        flash('Acesso restrito.', 'error')
        return redirect(url_for('dashboard'))

    session_db = Session()
    try:
        if request.method == 'POST':
            titulo = request.form.get('titulo')
            conteudo = request.form.get('conteudo')

            if not titulo or not conteudo:
                flash('Todos os campos são obrigatórios!', 'error')
                return redirect(url_for('comunicados'))

            comunicado = Comunicado(titulo=titulo, conteudo=conteudo, usuario_id=current_user.id, condominio_id=current_user.condominio.id)
            session_db.add(comunicado)
            session_db.commit()

            flash('Comunicado postado com sucesso!', 'success')
            return redirect(url_for('comunicados'))

        comunicados = session_db.query(Comunicado).filter(Comunicado.condominio_id == current_user.condominio.id).order_by(Comunicado.data_postagem.desc()).all()

        return render_template('comunicados.html', comunicados=comunicados)

    except Exception as e:
        session_db.rollback()
        app.logger.exception(f'Erro ao postar comunicado: {e}')
        flash('Erro ao postar comunicado. Tente novamente.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()

@app.route('/usuarios/gerenciar', methods=['GET', 'POST'])
@login_required
def gerenciar_usuarios():
    if current_user.tipo != TIPO_SINDICO:
        flash('Acesso restrito.', 'error')
        return redirect(url_for('dashboard'))

    session_db = Session()
    try:
        usuarios = session_db.query(Usuario).filter(Usuario.condominio_id == current_user.condominio.id).all()

        if request.method == 'POST':
            usuario_id = request.form.get('usuario_id')
            acao = request.form.get('acao')
            usuario = session_db.query(Usuario).get(usuario_id)

            if acao == 'ativar':
                usuario.is_ativo = True
            elif acao == 'desativar':
                usuario.is_ativo = False

            session_db.commit()
            flash(f'Usuário {usuario.nome} {"ativado" if usuario.is_ativo else "desativado"} com sucesso!', 'success')
            return redirect(url_for('gerenciar_usuarios'))

        return render_template('gerenciar_usuarios.html', usuarios=usuarios)

    except Exception as e:
        session_db.rollback()
        app.logger.exception(f'Erro ao gerenciar usuários: {e}')
        flash('Erro ao gerenciar usuários. Tente novamente.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()

# Execução local (produção: gunicorn)
if __name__ == '__main__':
    app.run(debug=True)
