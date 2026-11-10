# 🐱 Memória Gata

Jogo da memória com visual neon e um backend local para cadastro e autenticação de jogadores.

## Tecnologias

- Frontend: HTML, CSS e JavaScript
- Backend local: Python + Flask
- Banco de dados: SQLite (criado automaticamente em `instance/memoria_gata.sqlite3`)
- Senhas: hash scrypt via Werkzeug; nunca são armazenadas em texto puro
- Sessões: token aleatório no cookie HttpOnly e hash do token no SQLite

## Rodar localmente com login e banco de dados

> Para testar o cadastro e o login, inicie o Flask. Não use `python -m http.server`, pois esse servidor estático não atende às rotas da API.

1. Instale o Python 3.10 ou superior.
2. Clone o repositório e entre na pasta:
   ```cmd
   git clone https://github.com/Sodakk96/My_memorie.git
   cd My_memorie
   ```
3. Crie e ative um ambiente virtual:
   ```cmd
   py -m venv .venv
   .venv\Scripts\activate
   ```
4. Instale as dependências:
   ```cmd
   py -m pip install -r requirements.txt
   ```
5. Inicie o backend:
   ```cmd
   py app.py
   ```
6. Abra no navegador: http://127.0.0.1:5000

Na primeira execução, o SQLite cria automaticamente a pasta `instance` e o arquivo do banco de dados.

## Testar a autenticação

- Cadastre uma conta com nome, e-mail e senha (mínimo de 8 caracteres).
- Saia e entre novamente com o mesmo e-mail e senha.
- Atualize a página: a sessão deve continuar ativa.
- Use o botão **Sair** para encerrar a sessão.

Rotas disponíveis:

| Método | Rota | Função |
|---|---|---|
| GET | `/api/health` | Verifica se o backend está ativo |
| POST | `/api/register` | Cria usuário e inicia sessão |
| POST | `/api/login` | Autentica usuário |
| GET | `/api/me` | Retorna o usuário da sessão atual |
| POST | `/api/logout` | Encerra a sessão |

## Banco de dados local

O arquivo `instance/memoria_gata.sqlite3` é gerado na sua máquina e está no `.gitignore`; ele não será enviado ao GitHub. Para inspecionar o banco, use uma ferramenta SQLite ou o comando `sqlite3` se estiver instalado.

## Publicação

O backend Flask e o SQLite local são apenas para desenvolvimento. O Cloudflare Pages publica a versão estática do frontend; ele não executa este servidor Python nem compartilha o arquivo SQLite. Para publicar autenticação real, será necessário hospedar a API e usar um banco persistente apropriado.

## Build estático do Cloudflare Pages

O comando `npm run build` copia o frontend para `dist`. Isso mantém o deploy estático separado do backend local.


## Autenticação online (Cloudflare Pages + D1)

O login online usa Pages Functions e o banco Cloudflare D1. A API local Flask continua disponível para desenvolvimento local, mas o site publicado chama as rotas relativas `/api/*`.

- Banco D1: `memoria-gata-auth`
- Binding no Pages: `DB`
- Função: `functions/api/[[path]].js`
- Rotas: `GET /api/health`, `POST /api/register`, `POST /api/login`, `GET /api/me`, `POST /api/logout`

A tabela `users` armazena hash PBKDF2-SHA256 das senhas. A tabela `auth_sessions` guarda apenas o hash do token de sessão. O cookie de sessão é HttpOnly, Secure e SameSite=Lax.

O banco online foi criado e vinculado ao ambiente de produção do Pages. A aplicação publica automaticamente uma nova versão ao receber commits na branch `main`.
