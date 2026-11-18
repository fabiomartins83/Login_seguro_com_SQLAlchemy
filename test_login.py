import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from login_seguro_with_orm import Base, Usuario, ph, verificar_senha

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_criar_usuario_e_hash_senha(db_session):
    # Usa os nomes reais das colunas da classe Usuario
    senha_clara = "senha123"
    novo_user = Usuario(
        nome_usuario="teste_ci",
        senha_usuario=ph.hash(senha_clara)
    )
    
    db_session.add(novo_user)
    db_session.commit()

    # Busca o usuário no banco em memória usando o campo correto (nome_usuario)
    usuario_salvo = db_session.query(Usuario).filter_by(nome_usuario="teste_ci").first()

    # Validações com os atributos e funções reais do projeto
    assert usuario_salvo is not None
    assert usuario_salvo.nome_usuario == "teste_ci"
    # Garante que a senha foi criptografada com Argon2 (não fica em texto claro)
    assert usuario_salvo.senha_usuario != senha_clara
    assert verificar_senha(usuario_salvo.senha_usuario, senha_clara) is True
    assert verificar_senha(usuario_salvo.senha_usuario, "senha_errada") is False
