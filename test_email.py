import smtplib
import os
from dotenv import load_dotenv

# Carrega as mesmas variáveis de ambiente que sua app usa
load_dotenv()

# --- IMPORTANTE: Altere para o seu e-mail pessoal aqui ---
RECIPIENT_EMAIL = 'seu-email-de-teste@exemplo.com'
# ---------------------------------------------------------

# Pega as credenciais do ambiente
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
MAIL_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

print("--- INICIANDO TESTE DE E-MAIL ---")
print(f"Servidor: {MAIL_SERVER}:{MAIL_PORT}")
print(f"Usuário: {MAIL_USERNAME}")
print(f"Remetente: {MAIL_SENDER}")

if not all([MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_SENDER]):
    print("\n[ERRO] Variáveis de ambiente faltando! Verifique se todas estão configuradas no Render.")
    exit()

server = None
try:
    print("\n1. Conectando ao servidor SMTP...")
    server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=60)
    
    print("2. Iniciando TLS (conexão segura)...")
    server.starttls()
    
    print("3. Fazendo login...")
    server.login(MAIL_USERNAME, MAIL_PASSWORD)
    
    print("4. Enviando e-mail...")
    subject = "Teste de Conexão CondoIQ - Render"
    body = "Se você recebeu este e-mail, a conexão com o SendGrid está funcionando!"
    message = f"Subject: {subject}\n\n{body}"
    
    server.sendmail(MAIL_SENDER, RECIPIENT_EMAIL, message)
    
    print("\n[SUCESSO] E-mail enviado com sucesso! Verifique sua caixa de entrada.")

except smtplib.SMTPAuthenticationError as e:
    print(f"\n[ERRO DE AUTENTICAÇÃO] {e}")
    print("-> Causa provável: Sua variável 'MAIL_PASSWORD' (a chave da API) está incorreta.")

except Exception as e:
    print(f"\n[ERRO INESPERADO] Ocorreu um erro: {e}")

finally:
    if server:
        print("\n5. Fechando conexão.")
        server.quit()
    print("--- TESTE FINALIZADO ---")
