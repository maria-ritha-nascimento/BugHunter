# BugHunter

**BugHunter** é uma poderosa ferramenta de análise e diagnóstico de segurança, desenvolvida para auxiliar profissionais de TI e cibersegurança na identificação de vulnerabilidades e na realização de auditorias em sistemas e redes. A aplicação oferece funcionalidades como escaneamento de portas, análise de vulnerabilidades, inspeção de configurações DNS, verificação de certificados SSL/TLS, e geração automatizada de relatórios.

## 🚀 Funcionalidades

- **Port Scanner Avançado**: Detecta portas abertas em um alvo e identifica serviços comuns associados.
- **Vulnerability Scanner**: Integração com APIs de bases de dados como NIST para verificar vulnerabilidades conhecidas (CVE).
- **Web Application Scanner**: Analisa aplicações web para detecção de falhas como SQL Injection, XSS e Directory Traversal.
- **DNS Scanner**: Identifica subdomínios ativos e verifica registros DNS mal configurados.
- **SSL/TLS Scanner**: Verifica a validade e segurança dos certificados SSL/TLS.
- **Geração de Relatórios**: Produz relatórios detalhados em formato PDF ou JSON, incluindo resultados e recomendações de correção.

---

## 📂 Estrutura do Projeto

```plaintext
BugHunter/
├── app/
│   ├── __init__.py
│   ├── main.py         # Código principal da aplicação
│   └── static/
│       └── swagger.json # Documentação Swagger para os endpoints
├── tests/
│   ├── test_scanner.py # Testes unitários para a aplicação
├── requirements.txt     # Dependências do projeto
└── README.md            # Documentação do projeto
```

---

## 🛠️ Tecnologias Utilizadas

- **Linguagem**: Python 3.13+
- **Frameworks**:
  - Flask (desenvolvimento de APIs RESTful)
  - Flask-CORS (habilitação de CORS)
- **Bibliotecas de Terceiros**:
  - Requests (requisições HTTP)
  - BeautifulSoup (análise de HTML)
  - ReportLab (geração de relatórios em PDF)
- **Documentação**: Swagger UI

---

## 🌐 Onde o Cliente Pode Utilizar

BugHunter é ideal para:

- Empresas que desejam realizar auditorias de segurança interna.
- Profissionais de cibersegurança em busca de vulnerabilidades em redes e aplicações.
- Administradores de sistemas interessados em monitorar a saúde de seus servidores.
- Desenvolvedores que desejam melhorar a segurança de suas aplicações web.

---

## 🖥️ Como Executar o Projeto

### Pré-requisitos

- Python 3.13+ instalado em sua máquina.
- Instale as dependências com o `pip`:
  ```bash
  pip install -r requirements.txt
  ```

### Execução da Aplicação

1. Clone o repositório:
   ```bash
   git clone https://github.com/maria-ritha-nascimento/BugHunter.git
   cd BugHunter
   ```

2. Ative o ambiente virtual:
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/Mac
   venv\Scripts\activate      # Windows
   ```

3. Inicie a aplicação:
   ```bash
   python app/main.py
   ```

4. Acesse a interface Swagger:
   - Abra [http://127.0.0.1:5000/swagger/](http://127.0.0.1:5000/swagger/) no navegador.

---

### Testes Unitários

Para executar os testes:
```bash
pytest tests/test_scanner.py
```

---

## 📑 Documentação da API

A documentação completa dos endpoints está disponível na interface Swagger, acessível após a execução da aplicação em:

[http://127.0.0.1:5000/swagger/](http://127.0.0.1:5000/swagger/)

---

## 📬 Suporte e Feedback

Se você encontrar algum problema ou tiver sugestões para melhorias, sinta-se à vontade para abrir uma [issue no repositório](https://github.com/maria-ritha-nascimento/BugHunter/issues).

---

## 🏆 Contribuidores

- **Maria Ritha Nascimento** - Desenvolvedora principal.

Agradecemos por utilizar o **BugHunter** e esperamos que ele contribua para a segurança e sucesso de seus projetos!
