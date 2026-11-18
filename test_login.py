import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from login_seguro_with_orm import (
    Base, Usuario, ph, verificar_senha, 
    cadastrar_usuario, normalizar_usuario, 
    buscar_usuario_ativo, autenticar
)

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_criar_usuario_e_hash_senha(db_session):
    # Teste básico direto no modelo e verificação de hash[cite: 3]
    senha_clara = "senha123"
    novo_user = Usuario(
        nome_usuario="teste_ci",
        senha_usuario=ph.hash(senha_clara)
    )
    
    db_session.add(novo_user)
    db_session.commit()

    usuario_salvo = db_session.query(Usuario).filter_by(nome_usuario="teste_ci").first()

    assert usuario_salvo is not None
    assert usuario_salvo.nome_usuario == "teste_ci"
    assert usuario_salvo.senha_usuario != senha_clara
    assert verificar_senha(usuario_salvo.senha_usuario, senha_clara) is True
    assert verificar_senha(usuario_salvo.senha_usuario, "senha_errada") is False

def test_cadastrar_usuario_sucesso(db_session):
    # Testa o cadastro completo aplicando a política de senha forte
    sucesso = cadastrar_usuario(db_session, "novo_usuario", "SenhaForte123!", aplicar_politica=True)
    assert sucesso is True

    # Confirma que o usuário foi salvo e a senha foi convertida em hash Argon2id
    user_salvo = db_session.query(Usuario).filter_by(nome_usuario="novo_usuario").first()
    assert user_salvo is not None
    assert user_salvo.senha_usuario.startswith("$argon2id$")
    assert verificar_senha(user_salvo.senha_usuario, "SenhaForte123!") is True

def test_cadastrar_usuario_senha_fraca(db_session):
    # Tenta cadastrar com uma senha curta (abaixo de 10 caracteres) com política ativa
    with pytest.raises(ValueError, match="Senha fraca"):
        cadastrar_usuario(db_session, "usuario_fraco", "curta123", aplicar_politica=True)

    # Tenta cadastrar com uma senha muito comum da lista restrita
    with pytest.raises(ValueError, match="Senha fraca"):
        cadastrar_usuario(db_session, "usuario_comum", "password123", aplicar_politica=True)

def test_cadastrar_usuario_duplicado(db_session):
    # Cadastra o primeiro usuário com sucesso
    cadastrar_usuario(db_session, "fabio_teste", "SenhaForte123!", aplicar_politica=True)

    # Tenta cadastrar o mesmo nome de usuário novamente (deve retornar False por duplicidade)
    resultado = cadastrar_usuario(db_session, "FABIO_TESTE", "OutraSenhaForte456!", aplicar_politica=True)
    assert resultado is False

def test_normalizacao_e_case_insensitive_usuario(db_session):
    # Cadastra um usuário com letras maiúsculas e espaços (que serão normalizados)
    sucesso = cadastrar_usuario(db_session, "  FABIO.MARTINS  ", "SenhaForte123!", aplicar_politica=True)
    assert sucesso is True

    # Tenta buscar ou autenticar variando o case ou adicionando espaços (deve encontrar)
    usuario_encontrado = buscar_usuario_ativo(db_session, normalizar_usuario("fabio.martins"))
    assert usuario_encontrado is not None
    assert usuario_encontrado.nome_usuario == "fabio.martins"

def test_cadastrar_usuario_formato_invalido(db_session):
    # Testa caracteres proibidos no nome de usuário (ex: espaços no meio, @, símbolos)
    with pytest.raises(ValueError, match="Usuário ou senha fora do formato"):
        cadastrar_usuario(db_session, "usuario inválido", "SenhaForte123!", aplicar_politica=True)

    with pytest.raises(ValueError, match="Usuário ou senha fora do formato"):
        cadastrar_usuario(db_session, "usuario@teste", "SenhaForte123!", aplicar_politica=True)

def test_autenticar_sucesso_e_falha(db_session):
    # Cadastra um usuário válido
    cadastrar_usuario(db_session, "operador", "SenhaForte123!", aplicar_politica=True)

    # 1. Autenticação com credenciais corretas deve retornar o nome do usuário
    nome_autenticado = autenticar(db_session, "operador", "SenhaForte123!")
    assert nome_autenticado == "operador"

    # 2. Senha incorreta deve retornar None
    resultado_senha_errada = autenticar(db_session, "operador", "SenhaErrada999!")
    assert resultado_senha_errada is None

def test_tentativa_login_usuario_inexistente(db_session):
    # Tenta autenticar um usuário que não existe no banco.
    # O sistema deve rodar o fluxo com o HASH_FALSO e retornar None com segurança,
    # mantendo o tempo de resposta consistente (proteção contra timing attacks).
    resultado = autenticar(db_session, "usuario_fantasma", "QualquerSenha123!")
    assert resultado is None
