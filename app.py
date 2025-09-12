import os
from urllib.parse import quote_plus
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from sqlalchemy import create_engine, Column, Integer, String, Date, ForeignKey, Table, Boolean, text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
import bcrypt
import re
import secrets
import datetime
from smtplib import SMTPException
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError

load_dotenv()

# ============================================
# BANCO DE DADOS (Configuração Local)
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

# Log da URL com senha mascarada
try:
    from sqlalchemy.engine import url as sa_url
    _parsed = sa_url.make_url(DATABASE_URL)
    print("DB URL OK:", _parsed.set(password="***"))
except Exception as e:
    print("DATABASE_URL (montada via DB_*) inválida:", e)

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
TIPO_DESATIVADO = 3  # Nova constante para morador desativado

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
    mensagens_enviadas = relationship("Mensagem", back_populates="remetente")

    condominio = relationship("Condominio", back_populates="usuarios", lazy='select')
    reunioes = relationship("Reuniao", secondary=reuniao_participantes, back_populates="participantes")

    def is_authenticated(self): return True
    def is_active(self): return self.is_ativo
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)


class Mensagem(Base):
    __tablename__ = "mensagens"
    id = Column(Integer, primary_key=True)
    conteudo = Column(String(500), nullable=False)
    data_envio = Column(Date, default=datetime.date.today)
    remetente_id = Column(Integer, ForeignKey("usuarios.id"), nullable=False)
    reclamacao_id = Column(Integer, ForeignKey("reclamacoes.id"), nullable=False)

    remetente = relationship("Usuario", back_populates="mensagens_enviadas")
    reclamacao = relationship("Reclamacao", back_populates="mensagens")

class Reclamacao(Base):
    __tablename__ = "reclamacoes"
    id = Column(Integer, primary_key=True)
    titulo = Column(String(150), nullable=False)
    descricao = Column(String(500), nullable=False)
    data_abertura = Column(Date, default=datetime.date.today)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=False)
    usuario = relationship("Usuario", back_populates="reclamacoes")
    status = Column(String(50), default="Pendente")
    mensagens = relationship("Mensagem", back_populates="reclamacao", cascade="all, delete-orphan")

Usuario.reclamacoes = relationship("Reclamacao", back_populates="usuario")


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


class Comunicado(Base):
    __tablename__ = 'comunicados'
    id = Column(Integer, primary_key=True)
    titulo = Column(String(150), nullable=False)
    conteudo = Column(String(1000), nullable=False)
    data_postagem = Column(Date, default=datetime.date.today)
    usuario_id = Column(Integer, ForeignKey('usuarios.id'), nullable=False)
    condominio_id = Column(Integer, ForeignKey('condominio.id'), nullable=False)
    
    usuario = relationship("Usuario", back_populates="comunicados")
    condominio = relationship("Condominio", back_populates="comunicados")

Usuario.comunicados = relationship("Comunicado", back_populates="usuario")
Condominio.comunicados = relationship("Comunicado", back_populates="condominio")


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
    # Adicione esta nova coluna para o link do Meet:
    meet_link = Column(String(255), nullable=True) 
    # Mantenha as outras linhas
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
ALLOW_REGISTER_WITHOUT_EMAIL = os.getenv('ALLOW_REGISTER_WITHOUT_EMAIL', 'true').lower() == 'true'

@app.get("/healthz")
def healthz():
    return "ok", 200

@app.get("/dbcheck")
def dbcheck():
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
        return "db ok", 200
    except Exception as e:
        return f"db fail: {e}", 500

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
# E-MAIL (Configuração Local)
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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    step = request.values.get('step')
    session_db = Session()
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        codigo = request.form.get('codigo')
        try:
            if step != 'verify':
                if not nome or not email or not senha:
                    flash('Todos os campos são obrigatórios!', 'error')
                    return redirect(url_for('register'))
                if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    flash('Email inválido!', 'error')
                    return redirect(url_for('register'))
                if len(senha) < 8:
                    flash('A senha deve ter pelo menos 8 caracteres!', 'error')
                    return redirect(url_for('register'))
                if session_db.query(Usuario).filter_by(email=email).first():
                    flash('Email já cadastrado!', 'error')
                    return redirect(url_for('register'))

                verification_code = secrets.token_hex(3)
                session['verification_code'] = verification_code
                session['pending_registration'] = {'nome': nome, 'email': email, 'senha': senha}

                enviado = send_email(
                    'Código de Verificação - CondoIQ',
                    [email],
                    f'Seu código de verificação é: {verification_code}'
                )

                if not enviado and not ALLOW_REGISTER_WITHOUT_EMAIL:
                    flash('Não foi possível enviar o e-mail de verificação. Verifique as configurações de e-mail.', 'error')
                    return redirect(url_for('register'))

                if not enviado and ALLOW_REGISTER_WITHOUT_EMAIL:
                    app.logger.warning(f'EMAIL NÃO ENVIADO (modo teste). Código: {verification_code}')
                    session['show_verification_code'] = verification_code
                    flash('E-mail não enviado (modo teste). Use o código exibido na tela de verificação.', 'warning')
                else:
                    flash('Um código de verificação foi enviado para o seu email. Insira-o para confirmar.', 'success')

                return redirect(url_for('register', step='verify'))

            else:
                if not codigo or codigo != session.get('verification_code'):
                    flash('Código de verificação inválido!', 'error')
                    return redirect(url_for('register', step='verify'))

                hashed_senha = bcrypt.hashpw(session['pending_registration']['senha'].encode('utf-8'), bcrypt.gensalt())
                condominio_existente = session_db.query(Condominio).first()
                if not condominio_existente:
                    novo_usuario = Usuario(
                        nome=session['pending_registration']['nome'],
                        email=session['pending_registration']['email'],
                        senha=hashed_senha.decode('utf-8'),
                        tipo=TIPO_SINDICO
                    )
                    condominio_inicial = Condominio(
                        nome="Aquarela",
                        endereco="Rua 06 chácara 244",
                        status="ativo",
                        cnpj="04341404000108",
                        email="AquarelaCondoIQ@gmail.com"
                    )
                    session_db.add(condominio_inicial)
                    novo_usuario.condominio = condominio_inicial
                else:
                    novo_usuario = Usuario(
                        nome=session['pending_registration']['nome'],
                        email=session['pending_registration']['email'],
                        senha=hashed_senha.decode('utf-8'),
                        tipo=TIPO_PENDENTE
                    )
                    novo_usuario.condominio = condominio_existente

                session_db.add(novo_usuario)
                session_db.commit()

                session.pop('verification_code', None)
                session.pop('pending_registration', None)
                session.pop('show_verification_code', None)

                flash('Registro concluído! Aguarde aprovação do síndico.', 'success')
                return redirect(url_for('login'))

        except Exception as e:
            session_db.rollback()
            app.logger.exception(f'Erro no registro: {e}')
            flash(f'Erro ao processar registro: {str(e)}', 'error')
            return redirect(url_for('register', step=step))
        finally:
            session_db.close()

    if step == 'verify':
        return render_template('verify.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identificador = request.form.get('identificador')
        senha = request.form.get('senha')
        session_db = Session()
        try:
            usuario = session_db.query(Usuario).filter_by(email=identificador).first()
            if not usuario or not bcrypt.checkpw(senha.encode('utf-8'), usuario.senha.encode('utf-8')):
                flash('Credenciais inválidas!', 'error')
                return redirect(url_for('login'))
            if not usuario.is_ativo:
                flash('Sua conta está desativada. Contate o síndico.', 'error')
                return redirect(url_for('login'))
            if usuario.tipo == TIPO_PENDENTE:
                flash('Seu cadastro foi realizado, mas o síndico precisa aprovar antes de você acessar o sistema.', 'warning')
                return redirect(url_for('login'))

            login_user(usuario)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        finally:
            session_db.close()
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    session_db = Session()
    step = request.args.get('step', 'send_code')
    if request.method == 'POST':
        try:
            if step == 'send_code':
                email = request.form.get('email')
                usuario = session_db.query(Usuario).filter_by(email=email).first()
                if not usuario:
                    flash('Email não encontrado!', 'error')
                    return redirect(url_for('forgot_password'))

                reset_code = secrets.token_hex(3)
                session['reset_code'] = reset_code
                session['reset_email'] = email

                enviado = send_email(
                    'Código de Redefinição de Senha - CondoIQ',
                    [email],
                    f'Seu código de redefinição de senha é: {reset_code}',
                    f'Seu código de redefinição de senha é: <b>{reset_code}</b>'
                )

                if not enviado and not ALLOW_REGISTER_WITHOUT_EMAIL:
                    flash('Não foi possível enviar o e-mail de redefinição. Verifique as configurações de e-mail.', 'error')
                    return redirect(url_for('forgot_password'))

                if not enviado and ALLOW_REGISTER_WITHOUT_EMAIL:
                    app.logger.warning(f'EMAIL NÃO ENVIADO (modo teste). Código reset: {reset_code}')
                    session['show_reset_code'] = reset_code
                    flash('E-mail não enviado (modo teste). Use o código exibido para continuar.', 'warning')
                else:
                    flash('Um código de redefinição foi enviado para o seu email. Insira-o para continuar.', 'success')

                return redirect(url_for('forgot_password', step='verify'))

            elif step == 'verify':
                codigo = request.form.get('codigo')
                email_session = session.get('reset_email')
                if not email_session:
                    flash('Sessão expirada. Tente novamente.', 'error')
                    return redirect(url_for('forgot_password'))
                if not codigo or codigo != session.get('reset_code'):
                    flash('Código de redefinição inválido!', 'error')
                    return redirect(url_for('forgot_password', step='verify'))

                flash('Código verificado com sucesso. Agora insira sua nova senha.', 'success')
                return redirect(url_for('forgot_password', step='reset'))

            elif step == 'reset':
                nova_senha = request.form.get('nova_senha')
                email_session = session.get('reset_email')
                if not email_session:
                    flash('Sessão expirada. Tente novamente.', 'error')
                    return redirect(url_for('forgot_password'))
                if len(nova_senha) < 8:
                    flash('A nova senha deve ter pelo menos 8 caracteres!', 'error')
                    return redirect(url_for('forgot_password', step='reset'))

                usuario = session_db.query(Usuario).filter_by(email=email_session).first()
                hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
                usuario.senha = hashed_senha.decode('utf-8')
                session_db.commit()

                session.pop('reset_code', None)
                session.pop('reset_email', None)
                session.pop('show_reset_code', None)

                flash('Senha redefinida com sucesso! Faça login com a nova senha.', 'success')
                return redirect(url_for('login'))

        except Exception as e:
            session_db.rollback()
            app.logger.exception(f'Erro na recuperação de senha: {e}')
            flash(f'Erro ao processar recuperação: {str(e)}. Verifique suas configurações de email.', 'error')
            return redirect(url_for('forgot_password', step=step))
        finally:
            session_db.close()

    return render_template('forgot_password.html', step=step)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('home'))

# No app.py, na rota /dashboard:
@app.route('/dashboard')
@login_required
def dashboard():
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        if not usuario_ativo or not usuario_ativo.condominio:
            return render_template('no_condominio.html', user=usuario_ativo)

        condominio = usuario_ativo.condominio

        if usuario_ativo.tipo == TIPO_SINDICO:
            despesas_condominio = session_db.query(Despesa).filter_by(condominio_id=condominio.id).all()
            reunioes_condominio = session_db.query(Reuniao).filter_by(condominio_id=condominio.id).all()
            moradores_condominio = session_db.query(Usuario).filter(Usuario.condominio_id == condominio.id).count()
            comunicados_condominio = session_db.query(Comunicado).filter_by(condominio_id=condominio.id).order_by(Comunicado.data_postagem.desc()).all()
            
            return render_template('dashboard_sindico.html',
                                   condominio=condominio,
                                   user=usuario_ativo,
                                   despesas=despesas_condominio,
                                   reunioes=reunioes_condominio,
                                   moradores=moradores_condominio,
                                   comunicados=comunicados_condominio)
        else:
            reunioes_morador = usuario_ativo.reunioes
            comunicados_condominio = session_db.query(Comunicado).filter_by(condominio_id=usuario_ativo.condominio_id).order_by(Comunicado.data_postagem.desc()).all()
            
            return render_template('dashboard_morador.html',
                                   condominio=condominio,
                                   user=usuario_ativo,
                                   reunioes=reunioes_morador,
                                   comunicados=comunicados_condominio)
    except Exception as e:
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('home'))
    finally:
        session_db.close()


# ===========================
# Gerenciar moradores (pendentes)
# ===========================
from sqlalchemy.exc import IntegrityError

@app.route('/moradores/pendentes', endpoint='moradores_pendentes')
@login_required
def _moradores_pendentes():
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        pendentes = session_db.query(Usuario).filter(
            Usuario.condominio_id == usuario_ativo.condominio_id,
            Usuario.tipo == TIPO_PENDENTE
        ).all()

        return render_template('gerenciar_moradores.html',
                               user=usuario_ativo,
                               pendentes=pendentes)
    except Exception as e:
        app.logger.exception(f'Erro em moradores_pendentes: {e}')
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()


@app.route('/moradores/<int:usuario_id>/negar', methods=['POST'], endpoint='negar_morador')
@login_required
def _negar_morador(usuario_id):
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        morador = session_db.query(Usuario).get(usuario_id)
        if not morador or morador.condominio_id != usuario_ativo.condominio_id:
            flash('Morador não encontrado.', 'error')
            return redirect(url_for('moradores_pendentes'))

        if morador.tipo != TIPO_PENDENTE:
            flash('Este usuário já foi processado.', 'warning')
            return redirect(url_for('moradores_pendentes'))

        morador.is_ativo = False
        session_db.commit()

        flash('Registro negado com sucesso.', 'success')
        return redirect(url_for('moradores_pendentes'))
    except Exception as e:
        session_db.rollback()
        app.logger.exception(f'Erro ao negar morador: {e}')
        flash(f'Erro ao negar: {e}', 'error')
        return redirect(url_for('moradores_pendentes'))
    finally:
        session_db.close()



@app.route('/moradores/<int:usuario_id>/aprovar', methods=['POST'], endpoint='aprovar_morador')
@login_required
def _aprovar_morador(usuario_id):
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        morador = session_db.query(Usuario).get(usuario_id)
        if not morador or morador.condominio_id != usuario_ativo.condominio_id:
            flash('Morador não encontrado.', 'error')
            return redirect(url_for('moradores_pendentes'))

        if morador.tipo != TIPO_PENDENTE:
            flash('Este usuário já foi processado.', 'warning')
            return redirect(url_for('moradores_pendentes'))

        morador.tipo = TIPO_MORADOR
        morador.is_ativo = True
        session_db.commit()

        flash('Morador aprovado com sucesso!', 'success')
        return redirect(url_for('moradores_pendentes'))
    except Exception as e:
        session_db.rollback()
        app.logger.exception(f'Erro ao aprovar morador: {e}')
        flash(f'Erro ao aprovar: {e}', 'error')
        return redirect(url_for('moradores_pendentes'))
    finally:
        session_db.close()


# ============================================
# Gerenciar usuários (Ativos e Desativados)
# ============================================

@app.route('/usuarios/gerenciar', methods=['GET', 'POST'])
@login_required
def gerenciar_usuarios():
    if current_user.tipo != TIPO_SINDICO:
        flash('Acesso restrito.', 'error')
        return redirect(url_for('dashboard'))

    session_db = Session()
    try:
        usuario_ativo_db = session_db.get(Usuario, current_user.id)
        
        usuarios_condominio = session_db.query(Usuario).filter(
            Usuario.condominio_id == usuario_ativo_db.condominio_id,
            Usuario.tipo != TIPO_SINDICO
        ).all()
        
        if request.method == 'POST':
            usuario_id = request.form.get('usuario_id')
            acao = request.form.get('acao')
            usuario = session_db.query(Usuario).get(usuario_id)

            if usuario is None or usuario.condominio_id != usuario_ativo_db.condominio_id:
                flash('Usuário não encontrado ou não pertence ao seu condomínio!', 'error')
                return redirect(url_for('gerenciar_usuarios'))

            if acao == 'ativar':
                if usuario.tipo == TIPO_DESATIVADO or usuario.tipo == TIPO_PENDENTE:
                    usuario.tipo = TIPO_MORADOR
                usuario.is_ativo = True
                flash(f'Usuário {usuario.nome} ativado com sucesso!', 'success')
            elif acao == 'desativar':
                usuario.is_ativo = False
                usuario.tipo = TIPO_DESATIVADO
                flash(f'Usuário {usuario.nome} desativado com sucesso!', 'success')
            else:
                flash('Ação inválida!', 'error')
            
            session_db.commit()
            return redirect(url_for('gerenciar_usuarios'))

        return render_template('gerenciar_usuarios.html', usuarios=usuarios_condominio)

    except Exception as e:
        session_db.rollback()
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()



@app.route('/abrir_reclamacao', methods=['GET', 'POST'])
@login_required
def abrir_reclamacao():
    if request.method == 'POST':
        titulo = request.form.get('titulo')
        descricao = request.form.get('descricao')

        if not titulo or not descricao:
            flash('Todos os campos são obrigatórios!', 'error')
            return redirect(url_for('abrir_reclamacao'))

        try:
            session_db = Session()
            # Cria a reclamação
            reclamacao = Reclamacao(titulo=titulo, descricao=descricao, usuario_id=current_user.id)
            session_db.add(reclamacao)
            session_db.flush() # Salva a reclamação para obter o ID

            # Cria a primeira mensagem (a própria reclamação)
            primeira_mensagem = Mensagem(
                conteudo=descricao,
                remetente_id=current_user.id,
                reclamacao_id=reclamacao.id
            )
            session_db.add(primeira_mensagem)
            session_db.commit()

            flash('Reclamação enviada com sucesso!', 'success')
            return redirect(url_for('reclamacao_chat', reclamacao_id=reclamacao.id))
        except Exception as e:
            session_db.rollback()
            app.logger.exception(f'Erro ao criar reclamação: {e}')
            flash('Erro ao abrir reclamação. Tente novamente.', 'error')
            return redirect(url_for('abrir_reclamacao'))
        finally:
            session_db.close()
    
    return render_template('abrir_reclamacao.html')

# Adicione esta nova rota no seu app.py, junto das outras rotas
@app.route('/reclamacoes/<int:reclamacao_id>', methods=['GET', 'POST'], endpoint='reclamacao_chat')
@login_required
def reclamacao_chat(reclamacao_id):
    session_db = Session()
    try:
        reclamacao = session_db.query(Reclamacao).get(reclamacao_id)
        if not reclamacao:
            flash('Reclamação não encontrada.', 'error')
            return redirect(url_for('dashboard'))

        # Verifica se o usuário tem permissão para ver esta reclamação
        # Acesso permitido se for o dono da reclamação ou se for um síndico do mesmo condomínio
        if not (current_user.id == reclamacao.usuario_id or (current_user.tipo == TIPO_SINDICO and current_user.condominio_id == reclamacao.usuario.condominio_id)):
            flash('Acesso negado.', 'error')
            return redirect(url_for('dashboard'))

        # Lógica para enviar uma nova mensagem (POST)
        if request.method == 'POST':
            conteudo = request.form.get('conteudo')
            if conteudo:
                nova_mensagem = Mensagem(
                    conteudo=conteudo,
                    remetente_id=current_user.id,
                    reclamacao_id=reclamacao.id
                )
                session_db.add(nova_mensagem)
                session_db.commit()
                flash('Mensagem enviada com sucesso!', 'success')
                return redirect(url_for('reclamacao_chat', reclamacao_id=reclamacao.id))
        
        # Lógica para visualizar o chat (GET)
        # As mensagens já vêm junto com a reclamação graças à relação `mensagens`
        mensagens_chat = reclamacao.mensagens
        
        return render_template('reclamacao_chat.html', reclamacao=reclamacao, mensagens=mensagens_chat, user=current_user)
    
    except Exception as e:
        session_db.rollback()
        app.logger.exception(f'Erro no chat da reclamação: {e}')
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()



@app.route('/reclamacoes', methods=['GET'], endpoint='lista_reclamacoes_sindico')
@login_required
def lista_reclamacoes_sindico():
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        reclamacoes = session_db.query(Reclamacao).join(Usuario).filter(
            Usuario.condominio_id == usuario_ativo.condominio_id
        ).all()

        # AQUI ESTÁ A CORREÇÃO: passando a variável 'user'
        return render_template('lista_reclamacoes_sindico.html', reclamacoes=reclamacoes, user=usuario_ativo)
    except Exception as e:
        session_db.rollback()
        app.logger.exception(f'Erro ao listar reclamações do síndico: {e}')
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()

# Adicione esta nova rota no seu app.py, junto com as outras
@app.route('/minhas_reclamacoes', methods=['GET'], endpoint='minhas_reclamacoes')
@login_required
def minhas_reclamacoes():
    session_db = Session()
    try:
        # Obtém todas as reclamações do usuário logado
        reclamacoes_morador = session_db.query(Reclamacao).filter_by(usuario_id=current_user.id).all()

        return render_template('minhas_reclamacoes.html', reclamacoes=reclamacoes_morador, user=current_user)
    except Exception as e:
        flash(f'Ocorreu um erro ao carregar suas reclamações: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()



# No seu app.py, adicione esta rota junto das outras
@app.route('/reclamacoes/<int:reclamacao_id>/concluir', methods=['POST'])
@login_required
def concluir_reclamacao(reclamacao_id):
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        reclamacao = session_db.get(Reclamacao, reclamacao_id)
        if not reclamacao or reclamacao.usuario.condominio_id != usuario_ativo.condominio_id:
            flash('Reclamação não encontrada ou você não tem permissão para esta ação.', 'error')
            return redirect(url_for('lista_reclamacoes_sindico'))

        reclamacao.status = 'Concluída'
        session_db.commit()
        flash(f'Reclamação "{reclamacao.titulo}" concluída com sucesso!', 'success')
        
    except Exception as e:
        session_db.rollback()
        flash(f'Ocorreu um erro ao concluir a reclamação: {e}', 'error')
    finally:
        session_db.close()
    
    return redirect(url_for('lista_reclamacoes_sindico'))


# --- Adicione esta nova rota ao seu app.py, junto com as outras ---
# No seu app.py, localize e substitua esta rota inteira
@app.route('/agendar_reuniao', methods=['GET', 'POST'])
@login_required
def agendar_reuniao():
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        # Lógica para processar o formulário
        if request.method == 'POST':
            titulo = request.form.get('titulo')
            data = request.form.get('data')
            local = request.form.get('local')
            meet_link = request.form.get('meet_link')
            participantes_ids = request.form.getlist('participantes')

            if not all([titulo, data, participantes_ids]) or not (local or meet_link):
                flash('Título, data, pelo menos um participante e um local (físico ou link do Meet) são obrigatórios!', 'error')
                return redirect(url_for('agendar_reuniao'))
            
            data_reuniao = datetime.datetime.strptime(data, '%Y-%m-%d').date()

            # Salva a reunião no banco de dados
            nova_reuniao = Reuniao(
                titulo=titulo,
                data=data_reuniao,
                local=local,
                condominio_id=usuario_ativo.condominio_id,
                meet_link=meet_link if meet_link else None
            )
            session_db.add(nova_reuniao)
            session_db.flush()

            # Adiciona os participantes
            participantes_convidados = session_db.query(Usuario).filter(Usuario.id.in_(participantes_ids)).all()
            nova_reuniao.participantes.extend(participantes_convidados)
            
            session_db.commit()

            # Envia e-mail para os participantes
            recipients = [p.email for p in participantes_convidados]
            send_email(
                subject=f'Nova Reunião Agendada: {titulo}',
                recipients=recipients,
                body=f"Olá, uma nova reunião foi agendada para o dia {data_reuniao.strftime('%d/%m/%Y')}. Título: {titulo}. Local: {local}. Link da reunião: {meet_link}",
                html=f"Olá, uma nova reunião foi agendada para o dia {data_reuniao.strftime('%d/%m/%Y')}.<br>"
                     f"Título: {titulo}<br>"
                     f"Local: {local}<br>"
                     f"Link da reunião: <a href='{meet_link}'>{meet_link}</a>"
            )

            flash('Reunião agendada com sucesso!', 'success')
            return redirect(url_for('dashboard'))

        # Lógica para exibir o formulário (GET)
        moradores = session_db.query(Usuario).filter(
            Usuario.condominio_id == usuario_ativo.condominio_id,
            Usuario.tipo.in_([TIPO_MORADOR, TIPO_PENDENTE])
        ).all()
        
        return render_template('agendar_reuniao.html', user=usuario_ativo, moradores=moradores)

    except Exception as e:
        session_db.rollback()
        flash(f'Ocorreu um erro: {e}', 'error')
        app.logger.exception(f'Erro na rota agendar_reuniao: {e}')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()

# No seu arquivo app.py, adicione esta rota:
@app.route('/comunicados', methods=['GET', 'POST'])
@login_required
def comunicados():
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        if request.method == 'POST':
            titulo = request.form.get('titulo')
            conteudo = request.form.get('conteudo')

            if not titulo or not conteudo:
                flash('Título e conteúdo são obrigatórios!', 'error')
                return redirect(url_for('comunicados'))

            novo_comunicado = Comunicado(
                titulo=titulo,
                conteudo=conteudo,
                usuario_id=usuario_ativo.id,
                condominio_id=usuario_ativo.condominio_id
            )
            session_db.add(novo_comunicado)
            session_db.commit()

            flash('Comunicado postado com sucesso!', 'success')
            return redirect(url_for('comunicados'))
        
        # Para requisições GET, busca e exibe os comunicados
        comunicados_existentes = session_db.query(Comunicado).filter_by(
            condominio_id=usuario_ativo.condominio_id
        ).order_by(Comunicado.data_postagem.desc()).all()

        return render_template('comunicados_sindico.html',
                               user=usuario_ativo,
                               comunicados=comunicados_existentes)
    except Exception as e:
        session_db.rollback()
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        session_db.close()





# No seu arquivo app.py, adicione estas duas novas rotas:

@app.route('/editar_comunicado/<int:comunicado_id>', methods=['GET', 'POST'])
@login_required
def editar_comunicado(comunicado_id):
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)
        comunicado_a_editar = session_db.get(Comunicado, comunicado_id)

        if not comunicado_a_editar or comunicado_a_editar.condominio_id != usuario_ativo.condominio_id:
            flash('Comunicado não encontrado ou você não tem permissão para editá-lo.', 'error')
            return redirect(url_for('comunicados'))

        if request.method == 'POST':
            comunicado_a_editar.titulo = request.form.get('titulo')
            comunicado_a_editar.conteudo = request.form.get('conteudo')
            session_db.commit()
            flash('Comunicado editado com sucesso!', 'success')
            return redirect(url_for('comunicados'))

        return render_template('editar_comunicado.html', 
                               comunicado=comunicado_a_editar,
                               user=usuario_ativo)
    except Exception as e:
        session_db.rollback()
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('comunicados'))
    finally:
        session_db.close()

@app.route('/excluir_comunicado/<int:comunicado_id>', methods=['POST'])
@login_required
def excluir_comunicado(comunicado_id):
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)
        comunicado_a_excluir = session_db.get(Comunicado, comunicado_id)
        
        if not comunicado_a_excluir or comunicado_a_excluir.condominio_id != usuario_ativo.condominio_id:
            flash('Comunicado não encontrado ou você não tem permissão para excluí-lo.', 'error')
            return redirect(url_for('comunicados'))
        
        session_db.delete(comunicado_a_excluir)
        session_db.commit()
        flash('Comunicado excluído com sucesso!', 'success')
        return redirect(url_for('comunicados'))
    except Exception as e:
        session_db.rollback()
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('comunicados'))
    finally:
        session_db.close()


# Adicione esta nova rota ao seu app.py, junto com as outras rotas:
@app.route('/usuarios/<int:usuario_id>/excluir', methods=['POST'])
@login_required
def excluir_usuario(usuario_id):
    session_db = Session()
    try:
        usuario_ativo = session_db.get(Usuario, current_user.id)
        requer_sindico(usuario_ativo)

        usuario_a_excluir = session_db.get(Usuario, usuario_id)

        if not usuario_a_excluir or usuario_a_excluir.condominio_id != usuario_ativo.condominio_id:
            flash('Usuário não encontrado ou você não tem permissão para esta ação.', 'error')
            return redirect(url_for('gerenciar_usuarios'))

        # Impede o síndico de excluir a si mesmo
        if usuario_a_excluir.id == usuario_ativo.id:
            flash('Você não pode excluir a si mesmo.', 'error')
            return redirect(url_for('gerenciar_usuarios'))

        # Se o usuário a ser excluído for um síndico, a exclusão não é permitida sem um novo síndico
        if usuario_a_excluir.tipo == TIPO_SINDICO:
            flash('Não é possível excluir o síndico. Nomeie um novo síndico primeiro, se necessário.', 'error')
            return redirect(url_for('gerenciar_usuarios'))

        session_db.delete(usuario_a_excluir)
        session_db.commit()
        flash(f'Usuário {usuario_a_excluir.nome} excluído com sucesso.', 'success')

    except Exception as e:
        session_db.rollback()
        flash(f'Ocorreu um erro: {e}', 'error')
    finally:
        session_db.close()
    
    return redirect(url_for('gerenciar_usuarios'))


# Execução local (produção: gunicorn)
if __name__ == '__main__':
    app.run(debug=True)