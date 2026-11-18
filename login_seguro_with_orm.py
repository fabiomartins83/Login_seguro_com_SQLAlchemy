# !pip install argon2-cffi sqlalchemy
import hashlib
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from getpass import getpass

# from logging.handlers import RotatingFileHandler
from pathlib import Path

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import orm

# ======================================================================
# Configuração
# ======================================================================

class ErroDeConfiguracao(RuntimeError):
    """Problema de configuração, com mensagem segura para exibir ao usuário."""

# Pasta privada para banco e log. No Colab o home é /root: fica fora de /content
# e do Google Drive. Pode ser trocada pela variável de ambiente LOGIN_SEGURO_DIR.
PASTA_DADOS = Path(os.environ.get("LOGIN_SEGURO_DIR") or Path.home() / ".login_seguro")
BANCO = PASTA_DADOS / "sistema.db"
ARQUIVO_LOG = PASTA_DADOS / "tentativas.log"

MAX_TENTATIVAS = 10
TAMANHO_MAX = 100
TAMANHO_MIN_SENHA = 10  # política de cadastro (não vale para a tentativa de login)

# Atraso crescente entre tentativas falhas, em segundos: 1, 2, 4, 8, 16, 30, 30...
ATRASO_BASE = 1.0
ATRASO_MAX = 30.0

# Em True, erros inesperados mostram o traceback completo (só para depuração)
MODO_DEPURACAO = os.environ.get("LOGIN_SEGURO_DEBUG") == "1"

# Nome de usuário: só letras minúsculas ASCII, números, ponto, hífen e sublinhado
PADRAO_USUARIO = re.compile(rf"[a-z0-9_.-]{{1,{TAMANHO_MAX}}}")

# Parâmetros do Argon2 definidos explicitamente (não dependem da versão da biblioteca)
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def gerar_hash_falso() -> str:
    """Gera um hash falso com salt aleatório para timing attacks."""
    return ph.hash(secrets.token_urlsafe(16))

# Hash de uma senha aleatória descartada: usado quando o usuário não existe,
# para que o tempo de resposta seja o mesmo nos dois casos
HASH_FALSO = gerar_hash_falso()

# ======================================================================
# Modelo (tabela tbUsuarios)
# ======================================================================

class Base(orm.DeclarativeBase):
    pass

class Usuario(Base):
    """Constraints: o banco rejeita dados inválidos mesmo se o código falhar."""

    __tablename__ = "tbUsuarios"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    nome_usuario: orm.Mapped[str] = orm.mapped_column(sa.Text, unique=True)
    senha_usuario: orm.Mapped[str] = orm.mapped_column(sa.Text)
    Inativo: orm.Mapped[bool] = orm.mapped_column(
        sa.Boolean(create_constraint=True, name="ck_inativo_booleano"),
        default=False,
        server_default=sa.text("0"),
    )

    __table_args__ = (
        sa.CheckConstraint("length(nome_usuario) BETWEEN 1 AND 100", name="ck_nome_tamanho"),
        sa.CheckConstraint("nome_usuario NOT GLOB '*[^a-z0-9_.-]*'", name="ck_nome_caracteres"),
        # Só hash Argon2id entra na coluna: senha em texto puro é recusada pelo banco
        # (GLOB diferencia maiúsculas de minúsculas; o LIKE do SQLite não)
        sa.CheckConstraint("senha_usuario GLOB '$argon2id$*'", name="ck_senha_argon2id"),
    )


# ======================================================================
# Normalização e validação de entrada
# ======================================================================

def normalizar_usuario(texto: str) -> str:
    """NFKC unifica formas equivalentes (ex.: largura total); depois strip e minúsculas."""
    return unicodedata.normalize("NFKC", texto).strip().lower()

def normalizar_senha(texto: str) -> str:
    """Só NFKC: a mesma senha em teclados ou sistemas diferentes gera o mesmo hash.
    Mantido sem .strip() para preservar espaços intencionais nas bordas."""
    return unicodedata.normalize("NFKC", texto)

def usuario_valido(texto: str) -> bool:
    """Só caracteres permitidos e tamanho limitado (espera texto já normalizado)."""
    return PADRAO_USUARIO.fullmatch(texto) is not None

def senha_valida(texto: str) -> bool:
    """Não vazia e com tamanho limitado (espera texto já normalizado).
    Validação de FORMATO, usada no login; a força da senha é checada só no cadastro."""
    return 0 < len(texto) <= TAMANHO_MAX

# Lista pequena e local de senhas muito comuns (não substitui uma checagem de vazamentos)
SENHAS_COMUNS = {
    "password", "password1", "password12", "password123", "passw0rd123",
    "1234567890", "12345678910", "123456789012", "123456789a", "a123456789",
    "0123456789", "9876543210", "0987654321", "1111111111", "0000000000",
    "qwertyuiop", "qwerty12345", "qwerty123456", "1q2w3e4r5t", "1qaz2wsx3edc",
    "abcdefghij", "abc1234567", "iloveyou123", "letmein1234", "welcome1234",
    "admin12345", "administrator", "senha12345", "senha123456", "mudar12345",
    "brasil12345",
}
_SEQUENCIAS = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm")

def motivo_senha_fraca(senha: str, nome: str) -> str | None:
    """Política de senha, aplicada só no CADASTRO (espera texto já normalizado).
    Retorna o motivo da recusa ou None se a senha for aceitável."""
    minusculas = senha.casefold()
    if len(senha) < TAMANHO_MIN_SENHA:
        return f"use pelo menos {TAMANHO_MIN_SENHA} caracteres."
    if minusculas in SENHAS_COMUNS:
        return "essa senha é muito comum."
    if len(set(senha)) < 5:
        return "use mais caracteres diferentes."
    if any(minusculas in seq or minusculas in seq[::-1] for seq in _SEQUENCIAS):
        return "não use sequências como 1234567890 ou abcdefghij."
    if len(nome) >= 3 and nome in minusculas:
        return "a senha não pode conter o nome de usuário."
    return None


# ======================================================================
# Log (Desativado)
# ======================================================================

def impressao(texto: str) -> str:
    """Identificador curto para o log: não revela o texto digitado
    (que pode ser uma senha digitada no campo errado)."""
    return hashlib.sha256(texto[:TAMANHO_MAX].encode("utf-8")).hexdigest()[:8]

def configurar_log(caminho: Path = ARQUIVO_LOG, max_bytes: int = 1_000_000, backups: int = 3) -> None:
    """Log rotacionado (um atacante não consegue encher o disco).
    Nunca registra senhas nem o texto digitado como usuário."""
    # logging.basicConfig(
    #     handlers=[RotatingFileHandler(caminho, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")],
    #     level=logging.INFO,
    #     format="%(asctime)s %(levelname)s %(message)s",
    # )
    # Impede o SQLAlchemy de registrar comandos e parâmetros (nomes e hashes) no log
    # logging.getLogger("sqlalchemy").setLevel(logging.WARNING)

# ======================================================================
# Arquivos e pastas privados (Desativado)
# ======================================================================

# Pastas sincronizadas com a nuvem: o banco (com os hashes) não pode ficar nelas
DRIVE_DO_COLAB = Path("/content/drive")
PREFIXOS_SINCRONIZADOS = ("dropbox", "onedrive", "google drive", "googledrive",
                          "my drive", "mydrive", "icloud")

def em_pasta_sincronizada(pasta: Path) -> bool:
    """True se a pasta está no Google Drive do Colab ou em outra pasta sincronizada."""
    # pasta = pasta.resolve()  # segue links simbólicos
    # if DRIVE_DO_COLAB in (pasta, *pasta.parents):
    #     return True
    # return any(parte.lower().startswith(PREFIXOS_SINCRONIZADOS) for parte in pasta.parts)
    return False # Retorna sempre falso para permitir qualquer pasta

def restringir_permissao(caminho: Path, modo: int) -> None:
    """chmod explícito: o umask só vale para arquivos NOVOS. Sem efeito em Windows."""
    try:
        os.chmod(caminho, modo)
    except OSError:
        pass

def preparar_pasta_privada(pasta: Path) -> None:
    """Cria a pasta (acesso só do dono) e recusa locais sincronizados com a nuvem."""
    # if em_pasta_sincronizada(pasta):
    #     raise ErroDeConfiguracao(
    #         f"A pasta {pasta} está em um local sincronizado (Google Drive, Dropbox etc.). "
    #         "Use uma pasta privada, fora de pastas sincronizadas."
    #     )
    pasta.mkdir(mode=0o700, parents=True, exist_ok=True)
    restringir_permissao(pasta, 0o700)
    

# ======================================================================
# Banco de dados
# ======================================================================

def conectar(caminho: Path = BANCO) -> sa.engine.Engine:
    """Cria o engine do SQLAlchemy, com as chaves estrangeiras ativadas em cada conexão.
    Pasta e arquivo do banco ficam acessíveis só ao dono."""
    caminho = Path(caminho)
    preparar_pasta_privada(caminho.parent)
    # Cria o arquivo já com permissão 600 (um arquivo vazio é um banco SQLite válido)
    # e corrige a permissão de um banco que já existia com acesso mais aberto
    os.close(os.open(caminho, os.O_CREAT | os.O_RDWR, 0o600))
    restringir_permissao(caminho, 0o600)

    # hide_parameters: mensagens de erro não exibem os parâmetros da consulta (nomes e hashes)
    engine = sa.create_engine(
        sa.engine.URL.create("sqlite", database=str(caminho)),
        hide_parameters=True,
    )

    @sa.event.listens_for(engine, "connect")
    def ativar_chaves_estrangeiras(conexao_dbapi, _registro):
        cursor = conexao_dbapi.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    return engine

def criar_tabela(engine: sa.engine.Engine) -> None:
    """Cria a tabela se ela ainda não existir."""
    Base.metadata.create_all(engine)

def cadastrar_usuario(sessao: orm.Session, nome: str, senha: str, *,
                     aplicar_politica: bool = True) -> bool:
    """Insere um usuário (só o hash é gravado, nunca a senha em texto puro).
    Retorna False se o banco recusar por duplicidade (nome já existente).
    Levanta ValueError se nome ou senha estiverem fora do formato permitido
    ou se a senha não atender à política de força (aplicar_politica=True)."""
    nome = normalizar_usuario(nome)
    senha = normalizar_senha(senha)
    if not usuario_valido(nome) or not senha_valida(senha):
        raise ValueError("Usuário ou senha fora do formato permitido.")
    if aplicar_politica:
        motivo = motivo_senha_fraca(senha, nome)
        if motivo:
            raise ValueError(f"Senha fraca: {motivo}")

    sessao.add(Usuario(nome_usuario=nome, senha_usuario=ph.hash(senha)))
    try:
        sessao.commit()
    except sa.exc.IntegrityError as e:
        sessao.rollback()
        orig = getattr(e, "orig", None)
        if isinstance(orig, sqlite3.IntegrityError) and "unique" in str(orig).lower():
            return False
        raise  # Propaga caso seja violação de outras constraints
    return True

def preparar_banco(engine: sa.engine.Engine) -> None:
    """Cria a tabela e, se ela estiver vazia, cadastra o usuário de teste
    utilizando a variável de ambiente SENHA_INICIAL_TESTE ou 'password' como padrão."""
    criar_tabela(engine)
    with orm.Session(engine) as sessao:
        if sessao.scalar(sa.select(Usuario.id).limit(1)) is None:
            senha_teste = os.getenv("SENHA_INICIAL_TESTE", "password")
            if senha_teste:
                # Exceção à política de senha: só o usuário de teste
                cadastrar_usuario(sessao, "fabio", senha_teste, aplicar_politica=False)

def buscar_usuario_ativo(sessao: orm.Session, nome: str) -> Usuario | None:
    """Retorna o usuário ativo com esse nome, ou None.
    O SQLAlchemy usa parâmetros vinculados (?), o que evita SQL injection."""
    return sessao.scalar(
        sa.select(Usuario).where(Usuario.nome_usuario == nome, Usuario.Inativo == sa.false())
    )


# ======================================================================
# Autenticação
# ======================================================================

def verificar_senha(hash_salvo: str, senha: str) -> bool:
    """True se a senha confere com o hash; False se errada ou se o hash estiver corrompido."""
    try:
        return ph.verify(hash_salvo, senha)
    except (VerificationError, InvalidHashError):
        return False

def atualizar_hash_se_necessario(sessao: orm.Session, usuario: Usuario, senha: str) -> None:
    """Se os parâmetros do Argon2 mudaram, grava um hash novo."""
    if ph.check_needs_rehash(usuario.senha_usuario):
        usuario.senha_usuario = ph.hash(senha)
        sessao.commit()

def autenticar(sessao: orm.Session, nome: str, senha: str) -> str | None:
    """Retorna o nome do usuário se nome e senha conferirem, senão None.
    Sem registro (inexistente ou inativo), verifica contra o hash falso:
    tempo e mensagem de erro ficam iguais em todos os casos."""
    usuario = buscar_usuario_ativo(sessao, nome)
    hash_salvo = usuario.senha_usuario if usuario else HASH_FALSO
    if not verificar_senha(hash_salvo, senha) or usuario is None:
        return None
    nome_usuario = usuario.nome_usuario  # lido antes do commit, que expira os atributos
    atualizar_hash_se_necessario(sessao, usuario, senha)
    return nome_usuario

def tentar_login(sessao: orm.Session, usuario: str, senha: str) -> str | None:
    """Valida o formato e autentica (espera usuário e senha já normalizados)."""
    # [Nota de Segurança - Item 2]: Se migrado para Web/API, insira aqui a verificação
    # de Rate Limiting (ex: checar Redis por IP/Usuário antes de prosseguir).
    if usuario_valido(usuario) and senha_valida(senha):
        return autenticar(sessao, usuario, senha)
    return None


# ======================================================================
# Interface de terminal
# ======================================================================

def pedir_credenciais() -> tuple[str, str]:
    """Lê usuário e senha (a senha não aparece na tela) já normalizados."""
    usuario = normalizar_usuario(str(input("Usuário: ")))
    senha = normalizar_senha(str(getpass("Senha: ")))
    return usuario, senha

def calcular_atraso(falhas: int) -> float:
    """Atraso após a n-ésima falha: dobra a cada falha, até o limite ATRASO_MAX."""
    return min(ATRASO_BASE * 2 ** (falhas - 1), ATRASO_MAX)

def executar_login(sessao: orm.Session, max_tentativas: int = MAX_TENTATIVAS,
                    pedir=pedir_credenciais, esperar=None) -> str | None:
    """Repete o login até acertar ou esgotar as tentativas, com atraso crescente
    entre as falhas (esperar: função de espera; por padrão, time.sleep).
    Retorna o nome do usuário ou None."""
    esperar = esperar or time.sleep
    for numero in range(1, max_tentativas + 1):
        tentativa_usuario, tentativa_senha = pedir()
        nome_usuario = tentar_login(sessao, tentativa_usuario, tentativa_senha)

        if nome_usuario:
            # logging.info(
            #     "Login bem-sucedido: usuario=%r usuario_fp=%s",
            #     nome_usuario, impressao(tentativa_usuario),
            # )
            print(f"Bem-vindo ao sistema, {nome_usuario}.")
            return nome_usuario

        # logging.warning("Falha de login: usuario_fp=%s", impressao(tentativa_usuario))
        print("Falha de login: Usuário ou senha inválidos.")  # mesma mensagem para qualquer erro

        if numero < max_tentativas:  # após a última falha o programa encerra, sem espera
            atraso = calcular_atraso(numero)
            print(f"Aguarde {atraso:.0f} s antes de tentar novamente.")
            try:
                esperar(atraso)
            except (KeyboardInterrupt, SystemExit):
                raise

    # logging.warning("Limite de %d tentativas atingido", max_tentativas)
    print("Número máximo de tentativas atingido. Encerrando.")
    return None
    

def main() -> None:
    # Arquivos novos (banco, log, journal) já nascem acessíveis só ao dono
    os.umask(0o077)
    # configurar_log()
    engine = None
    try:
        engine = conectar()
        preparar_banco(engine)
        with orm.Session(engine) as sessao:
            executar_login(sessao)
    except (KeyboardInterrupt, EOFError):  # Ctrl+C ou Ctrl+D
        print("\nEncerrado.")
    except ErroDeConfiguracao as erro:  # mensagem controlada, segura para exibir
        print(f"Erro de configuração: {erro}")
    except Exception as erro:
        if MODO_DEPURACAO:
            raise
        # Só o TIPO do erro é exibido: a mensagem pode conter consultas, nomes e hashes
        print(f"Erro inesperado ({type(erro).__name__}). Encerrando.")
    finally:
        if engine is not None:
            engine.dispose()

if __name__ == "__main__":
    main()
