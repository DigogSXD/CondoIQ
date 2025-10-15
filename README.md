# CondoIQ - Sistema de Gestão de Condomínios

![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)

O **CondoIQ** é uma plataforma web completa para gestão de condomínios, desenvolvida em Python com o framework Flask. A solução visa centralizar e otimizar a comunicação entre síndicos e moradores, além de facilitar a administração de finanças, comunicados e ocorrências.

O sistema possui uma interface web robusta para o síndico e uma API RESTful projetada para ser consumida por um aplicativo mobile para os moradores.

***

## 🌟 Principais Funcionalidades

O sistema é dividido em dois níveis de acesso principais: **Síndico** e **Morador**.

### Para o Síndico (Interface Web)
* **Dashboard Administrativo:** Visão geral com acesso rápido às principais funções, como aprovações pendentes, despesas e comunicados.
* **Gestão de Moradores:**
    * Aprovar ou negar novos cadastros de moradores.
    * Ativar, desativar ou excluir perfis de usuários.
* **Gestão Financeira:**
    * Cadastro, edição e exclusão de despesas.
    * Filtro de despesas por competência (mês/ano) e categoria.
* **Comunicação Centralizada:**
    * Criação, edição e exclusão de comunicados para todos os moradores.
* **Gestão de Reclamações:**
    * Visualização de todas as reclamações abertas pelos moradores.
    * Interação via chat para responder e dar andamento às solicitações.
    * Marcar reclamações como "Concluídas".
* **Agendamento de Reuniões:**
    * Criação de novas reuniões (presenciais ou online via Google Meet).
    * Convocação de moradores específicos com envio de notificação por e-mail.
* **Controle de Acesso (IoT):** Integração para acionamento de portões através da plataforma Tuya.

### Para o Morador (via API para App Mobile)
* **Autenticação Segura:** Endpoints para login e logout.
* **Dashboard:** Acesso aos últimos comunicados e informações do condomínio.
* **Abertura de Reclamações:** Endpoint para registrar novas reclamações ou sugestões.
* **Comunicação:** Acesso à lista de comunicados publicados pelo síndico.
* **Controle de Acesso:** Endpoint dedicado para abrir o portão do condomínio diretamente pelo app.

***

## 🛠️ Tecnologias Utilizadas

* **Backend:** Python 3, Flask
* **Banco de Dados:** SQLAlchemy (ORM) com suporte para MySQL
* **Autenticação:** Flask-Login, Bcrypt para hashing de senhas
* **Envio de E-mails:** Flask-Mail, com integração para a API da SendGrid
* **Configuração:** `python-dotenv` para gerenciamento de variáveis de ambiente
* **Dependências Principais:** `Flask`, `SQLAlchemy`, `PyMySQL`, `bcrypt`, `Flask-Login`, `Flask-Mail`, `sendgrid`.

***

## 🚀 Como Executar o Projeto

Siga os passos abaixo para configurar e rodar o ambiente de desenvolvimento localmente.

### Pré-requisitos
* **Python 3.8+**
* Um servidor de banco de dados **MySQL** instalado e em execução.

### 1. Clone o Repositório
```bash
git clone [https://github.com/seu-usuario/seu-repositorio.git](https://github.com/seu-usuario/seu-repositorio.git)
cd seu-repositorio
```


### 2. Crie e Ative um Ambiente Virtual
# Para Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Para Windows
python -m venv venv
.\venv\Scripts\activate

### 3. Instale as Dependências
requirements.txt com o conteúdo abaixo e execute o comando pip install.

requirements.txt

```bash
pip install -r requirements.txt
```

### 4. Configure as Variáveis de Ambiente

# Configuração do Banco de Dados
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=sua_senha_do_banco
DB_NAME=condoiq_db
DB_SSL=false

# Chave secreta do Flask (gere uma chave segura)
SECRET_KEY='uma-chave-secreta-muito-forte-e-aleatoria'

# Configuração de E-mail (usando SendGrid)
# Deixe em branco se não for usar ou configure ALLOW_REGISTER_WITHOUT_EMAIL=true
SENDGRID_API_KEY='sua_chave_de_api_do_sendgrid'
MAIL_DEFAULT_SENDER='seu-email-verificado@sendgrid.com'

# Modo de Desenvolvimento
# Permite registrar usuários sem enviar e-mail de confirmação (útil para testes)
ALLOW_REGISTER_WITHOUT_EMAIL=true

### 5. Execute a Aplicação

```bash
python app.py
```


📡 Endpoints da API (para o App Mobile)
A API foi projetada para ser consumida por um aplicativo mobile, garantindo que os moradores tenham acesso às funcionalidades na palma da mão.

POST /api/login: Autentica o usuário e retorna os dados do perfil.

POST /api/logout: Efetua o logout do usuário.

GET /api/dashboard: Retorna dados essenciais para a tela inicial, como comunicados e informações do condomínio.

POST /api/abrir_reclamacao: Permite que o morador abra um novo chamado.

POST /api/abrir_portao: Envia o comando para acionar o portão (requer permissão especial).


# CondoIQ
https://console.aiven.io/account/a55d8b63050d/project/diogodbm9-2420/services/mysql-2e2b7701/overview\

https://app.sendgrid.com/settings/sender_auth/senders

https://dashboard.render.com/web/srv-d31gelu3jp1c73fsdu9g/events

https://condoiq.onrender.com/login

roda




