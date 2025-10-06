from __future__ import annotations
import os, time, hmac, hashlib, requests, uuid, json
from dotenv import load_dotenv

load_dotenv()

REGION = os.getenv('TUYA_REGION', 'openapi.tuyaus.com').strip()
CLIENT_ID = os.getenv('TUYA_CLIENT_ID', '').strip()
CLIENT_SECRET = os.getenv('TUYA_CLIENT_SECRET', '').strip()
DEVICE_ID = os.getenv('TUYA_DEVICE_ID', '').strip()
TUYA_CODE = os.getenv('TUYA_CODE', '').strip()
PULSE_MS = int(os.getenv('PULSE_MS', '800'))

def now_ms() -> str:
    return str(int(time.time() * 1000))

def hmac_upper(msg: str, secret: str) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256)
    return mac.hexdigest().upper()

EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
def build_string_to_sign(method: str, content_sha256: str, headers_block: str, path_with_query: str) -> str:
    return f"{method}\n{content_sha256}\n{headers_block}\n{path_with_query}"

def get_token() -> str:
    path = "/v1.0/token?grant_type=1"
    url = f"https://{REGION}{path}"
    t = now_ms()
    nonce = uuid.uuid4().hex
    string_to_sign = build_string_to_sign("GET", EMPTY_BODY_SHA256, "", path)
    sign_src = CLIENT_ID + t + nonce + string_to_sign
    sign = hmac_upper(sign_src, CLIENT_SECRET)
    
    headers = {
        "client_id": CLIENT_ID,
        "t": t,
        "nonce": nonce,
        "sign_method": "HMAC-SHA256",
        "sign": sign,
        "User-Agent": "open-gate-script/1.0"
    }
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json()
    if not data.get("success"):
        raise RuntimeError("Falha ao obter token: " + str(data))
    return data["result"]["access_token"]

def send_command(access_token: str, commands: list) -> dict:
    body = {"commands": commands}
    body_json = json.dumps(body, separators=(',',':'))
    content_sha = hashlib.sha256(body_json.encode('utf-8')).hexdigest()
    path = f"/v1.0/iot-03/devices/{DEVICE_ID}/commands"
    url = f"https://{REGION}{path}"
    t = now_ms()
    nonce = uuid.uuid4().hex
    string_to_sign = build_string_to_sign("POST", content_sha, "", path)
    sign_src = CLIENT_ID + access_token + t + nonce + string_to_sign
    sign = hmac_upper(sign_src, CLIENT_SECRET)
    
    headers = {
        "client_id": CLIENT_ID,
        "access_token": access_token,
        "t": t,
        "nonce": nonce,
        "sign_method": "HMAC-SHA256",
        "sign": sign,
        "Content-Type": "application/json",
        "User-Agent": "open-gate-script/1.0"
    }
    r = requests.post(url, data=body_json.encode('utf-8'), headers=headers, timeout=15)
    try:
        r.raise_for_status()
    except requests.HTTPError:
        print("Erro HTTP ao enviar comando:", r.status_code, r.text)
        raise
    return r.json()

# Esta é a nova função que o Flask vai chamar
def open_gate_tuya():
    """
    Executa a sequência de comandos para abrir o portão via Tuya API.
    Retorna um dicionário com o status da operação.
    """
    # Verificação de variáveis de ambiente
    if not (CLIENT_ID and CLIENT_SECRET and DEVICE_ID):
        return {"success": False, "message": "ERRO: configure TUYA_CLIENT_ID, TUYA_CLIENT_SECRET e TUYA_DEVICE_ID no .env"}
    if not TUYA_CODE:
        return {"success": False, "message": "ERRO: TUYA_CODE não definido no .env."}

    try:
        print("Pegando access_token...")
        token = get_token()
        print("access_token obtido.")
        
        print(f"Enviando ON para code '{TUYA_CODE}' no device {DEVICE_ID}...")
        resp_on = send_command(token, [{"code": TUYA_CODE, "value": True}])
        print("Resp ON:", resp_on)
        
        time.sleep(PULSE_MS / 1000.0)
        
        print(f"Enviando OFF para code '{TUYA_CODE}'...")
        resp_off = send_command(token, [{"code": TUYA_CODE, "value": False}])
        print("Resp OFF:", resp_off)
        print("Pulso concluído.")
        
        if resp_on.get("success") and resp_off.get("success"):
            return {"success": True, "message": "Comando para abrir portão enviado com sucesso."}
        else:
            return {"success": False, "message": "Um dos comandos Tuya falhou."}
            
    except requests.HTTPError as e:
        print("Erro HTTP:", e.response.status_code, e.response.text)
        return {"success": False, "message": f"Erro HTTP: {e.response.status_code} - {e.response.text}"}
    except Exception as e:
        print("Erro inesperado:", str(e))
        return {"success": False, "message": f"Erro inesperado: {str(e)}"}

# O bloco abaixo só é executado se o script for chamado diretamente via linha de comando
if __name__ == "__main__":
    result = open_gate_tuya()
    if not result["success"]:
        print(f"Falha ao abrir portão: {result['message']}")
    else:
        print("Portão aberto com sucesso.")