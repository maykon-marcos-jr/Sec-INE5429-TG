# Trabalho em grupo: Implementação de esquemas/protocolos criptográficos

> Profs. Jean Martina e Thaís Bardini Idalino

> Junho de 2026

> **Objetivo**:
- entender os aspectos teóricos e experimentais de algoritmos, protocolos ou aplicações de criptografia.

- Neste trabalho, os alunos devem escolher algum algoritmo, protocolo ou aplicação de criptografia.
- Devem estudar os aspectos teóricos da sua escolha, fazer um planejamento da implementação e relatar essa parte em um relatório técnico entregue no moodle.
- Depois, devem fazer a implementação do algoritmo/protocolo/aplicação, redigir um relatório completo e apresentar o trabalho e o código em execução em uma apresentação em sala de aula. Ideias de tópicos serão apresentadas no final deste documento.
- Espera-se um trabalho com complexidade média, com dedicação de pelo menos 10hs por integrante do grupo.

> **Grupos:**
- os grupos devem ter, no máximo, 3 integrantes.
- A escolha do grupo deve ser feita pelo moodle.

> **Avaliação**:
- O trabalho consiste em duas entregas e a nota será a média aritmética simples das duas:

1. **Relatório parcial**: documento pdf enviado pelo moodle com entrega em 28/06. Deve conter, no mínimo, as seguintes seções:
   1. **Introdução (10%)**: contextualização, com identificação do algoritmo/protocolo/aplicação escolhido e da motivação da escolha.
   2. **Desenvolvimento (60%)**: contendo o detalhamento teórico do esquema escolhido, com a explicação de como e porquê ele funciona. Encoraja-se também a apresentação de um mini-exemplo (exemplo de entrada e saída do algoritmo a ser implementado). É imprescindível a apresentação de referências bibliográficas e citação apropriada. **Trabalhos sem referências apropriadas recebem nota 0**. Alunos também **devem** indicar na seção de referências o uso de IA, indicando qual ferramenta foi utilizada e para qual finalidade.
   3. **Experimento (30%)**: descrever a implementação que será executada no próximo passo, com apresentação de pseudocódigo ou diagrama.
2. **Relatório completo**: Entregar o relatório completo com a implementação documentada do experimento em 05/07. Essa entrega deve conter o relatório atualizado e o código fonte. Algumas equipes podem ser sorteadas para apresentar presencialmente o trabalho no dia 09/07. Alunos que não entregarem relatório ou não apresentarem o trabalho recebem 0 nessa parte. Os seguintes critérios serão avaliados:
   1. quantidade de trabalho desenvolvido: 20%
   2. qualidade do trabalho feito: 30%
   3. nota individual da apresentação: 30%
   4. evidências que justifiquem o trabalho: 20%

## Ideias de temas

Apresentamos abaixo algumas sugestões de temas.
Os alunos estão livres para escolherem outros temas, mas recomendamos falar com os professores antes de iniciar o trabalho.

> **Observação**: O tema escolhido e quantidade de trabalho a ser desenvolvido deve ser proporcional à quantidade de membros na equipe.

### Criptografia pós-quântica:

a criptografia pós-quântica surgiu para explorar as possibilidades de novos algoritmos criptográficos, resistentes à computadores quânticos.
Uma possibilidade de tema é explorar o projeto Open Quantum Safe \[1\], que oferece bibliotecas \[2\] com implementação de diversos algoritmos pós-quânticos, e implementar alguma aplicação ou experimento pós-quântico.

Por exemplo:

1. Sistema de troca de mensagens pós-quântico, estilo telegram ou whatsapp;
2. Acordo de chaves pós-quântico com algum KEM (Key Encapsulation Mechanism);
3. Assinaturas digitais pós-quânticas e comparação com esquemas clássicos;
4. Comparação de algoritmos pós-quânticos (tamanhos de chaves, eficiência, etc);
5. Experimentos com TLS, SSH, certificados X.509, CMS, etc \[3\].

### Protocolos de distribuição de chaves

A criptografia, por si só, não resolve todos os problemas de comunicação segura. São necessários protocolos que nos permitam fazer, por exemplo, uma troca ou distribuição de chaves de maneira segura. Uma possibilidade de tema é o de explorar algum protocolo criptográfico de troca de chaves (visto ou não em aula).

Por exemplo:

1. Protocolo de troca de chaves Diffie-Hellman, com possibilidade de explorar a troca de chaves por duas ou mais partes, ou os ataques existentes no esquema inicial, ou a aplicação do esquema em algum problema prático \[5\];
2. Protocolo de pré-distribuição de chaves em redes, como por exemplo, o esquema KPS de Lee-Stinson \[5\]\[6\];
3. Esquemas de distribuição de chaves de sessão, como Needham-Shoroeder, Denning-Sacco vistos em aula e em \[5\]. Uma possibilidade é a de implementar o esquema e explorar as vulnerabilidades do mesmo, fazendo experimentos de ataques.
4. Um *esquema de threshold (*ou *secret sharing)* se preocupa em proteger uma informação de maneira que uma pessoa sozinha não seja capaz de decifrá-la. A ideia consiste em criar uma chave e distribuí-la para um grupo de participantes, de maneira que seja necessário um conjunto mínimo de *t* participantes para reconstruir a chave de decifrar a informação \[5\]\[16\]\[18\]\[19\]. Um dos esquemas mais populares é o de Shamir \[5\]\[17\]. Além disso, existem diversas aplicações \[16\]\[18\]\[19\]. Uma possibilidade aqui é a de implementação de algum esquema e análise/comparação. Outra possibilidade é aplicar o esquema para solucionar algum problema, como o de proteção de dados sensíveis, autorização de acesso, etc.

### Implementação e aplicação de esquemas criptográficos

Uma possibilidade de tema é a de explorar mais a fundo alguns esquemas criptográficos através da implementação/experimentação ou aplicação dos mesmos. Algumas idéias são apresentadas abaixo:

* Sistema estilo o assinador da ufsc, com **assinatura e verificação de documentos digitais**.
  * Aqui os alunos podem explorar não só a geração de um par de chaves, mas também a criação de certificados digitais.
  * Existe a possibilidade de usar diversos esquemas de assinatura digital, como o RSA, DSA, ECDSA, ou até mesmo algum esquema pós-quântico.
  * É permitido o uso de bibliotecas que implementam os algoritmos, como o bouncy-castle em java \[7\].
* Uma **máquina Enigma**, com cifragem e decifragem de mensagens. Aqui é importante estudar profundamente o seu funcionamento e implementá-lo.
  * Pode-se fazer uma aplicação ou até mesmo app que simula uma máquina enigma, ou explorar as vulnerabilidades e como ela foi quebrada \[8\] \[9\].
* Existem diversos **ataques conhecidos no RSA**.
  * Alguns ataques exploraram a fatoração do valor público n, como o *algoritmo Pollard p-1* \[5\]\[10\], Pollard rho \[5\]\[11\], ou *Dixon’s random squares* \[5\]\[12\].
  * Outros tentam descobrir o valor de phi(n) \[5\] ou atacar o expoente de decifragem de diversas maneiras \[5\].
  * Ao escolher esse tópico, espera-se que o aluno não só implemente mas também explique o raciocínio matemático por trás do ataque.
* **Criptografia homomórfica** permite realizar cálculos em cima de dados cifrados sem a necessidade de decifrá-los antes dos cálculos \[13\].
  * Existem diversas bibliotecas que implementam criptografia homomórfica e também diversos exemplos de aplicações \[14, 24\].
  * Uma aplicação interessante de criptografia homomórfica é a de votação eletrônica, que permite a contagem dos votos sem a necessidade de decifragem de cada um individualmente \[15\], ou até mesmo calcular média salarial em uma base de dados cifrada enquanto mantém a privacidade dos valores individuais.
  * Aplicações mais atuais envolvem o uso de criptografia homomórfica em aplicações de *machine learning*, onde modelos podem ser treinados com dados cifrados \[23\].
* **Searchable encryption** é uma técnica utilizada na proteção da privacidade dos dados \[20\].
  * Ela permite o armazenamento de dados na nuvem de maneira cifrada, enquanto permite a busca pelos dados sem revelar o que está sendo buscado ou vazar qualquer informação sobre os dados. Existem diversos tipos/técnicas de SE.
  * Uma direção seria a de explorar as técnicas e implementações/bibliotecas disponíveis e fazer algum experimento/comparação.
  * Outra ideia seria a de implementar alguma aplicação para técnica, como a de busca em uma base de dados cifrada.
* **Provas de conhecimento zero** (ZKP) são protocolos onde um provador quer convencer um verificador de que que possui determinado conhecimento ou habilidade, sem revelar o próprio conhecimento.
  * Um exemplo seria o de provar a maioridade sem revelar a idade de fato.
  * Esses protocolos são utilizados em diversas aplicações, como em blockchain para prover privacidade em transações \[21\], em votação eletrônica onde um indivíduo pode provar que pode votar sem violar a privacidade da sua identidade \[22\].
  * Uma ideia de trabalho seria focar em uma aplicação e explorar como ZKP pode auxiliar, explorando teoria e prática.
  * Outra ideia seria estudar as possíveis técnicas existentes e fazer comparações entre elas.

### Engenharia Segura e DevSecOps:

A área de DevSecOps visa integrar práticas de segurança em todas as etapas do ciclo de vida de desenvolvimento de software, promovendo a automação e a detecção precoce de vulnerabilidades. O objetivo é permitir que segurança, desenvolvimento e operações atuem de forma conjunta (“security as code”). Um bom trabalho nessa linha deve envolver experimentos práticos com ferramentas, pipelines ou políticas de segurança automatizadas.

Por exemplo:

* Pipeline de CI/CD seguro: construção de um pipeline em GitLab, GitHub Actions ou Jenkins com integração de ferramentas de segurança como análise estática (SAST), análise dinâmica (DAST) e verificação de dependências (dependency scanning). O grupo pode explorar ferramentas como SonarQube, Semgrep, OWASP ZAP ou Trivy e apresentar resultados de vulnerabilidades detectadas e tratadas.

* Segurança como código (Security as Code): criação de políticas automatizadas usando Open Policy Agent (OPA) ou ferramentas equivalentes, aplicadas em pipelines ou ambientes Kubernetes. O trabalho pode demonstrar como políticas de acesso, rede e conformidade podem ser definidas e validadas automaticamente.

* Assinatura e verificação de artefatos: implementação de uma cadeia de confiança para o build e deploy, utilizando ferramentas como Cosign e Sigstore. A equipe pode demonstrar como assinar imagens Docker e verificar a autenticidade antes da publicação.

* Gestão segura de segredos: experimentação com HashiCorp Vault, Kubernetes Secrets ou AWS Secrets Manager, mostrando como armazenar e acessar credenciais de maneira segura durante o processo de desenvolvimento e execução.

* Análise e escaneamento de containers: construção de um ambiente com múltiplas imagens Docker e uso de scanners de vulnerabilidade (Trivy, Grype, Anchore) para detecção e mitigação de falhas conhecidas.

## Referências
* \[1\] [Open Quantum Safe](https://openquantumsafe.org/)
* \[2\] [Open Quantum Safe · GitHub](https://github.com/open-quantum-safe)
* \[3\] [Applications and protocols | Open Quantum Safe](https://openquantumsafe.org/applications/)
* \[4\] [Applications and protocols | Open Quantum Safe](https://openquantumsafe.org/applications/)
* \[5\] Stinson and Paterson, Cryptography: Theory and Practice, 4a edição, 2018\.
* \[6\] Lee and Stinson, A combinatorial approach to key predistribution for distributed sensor networks, 2005\. Link do [artigo original](https://ieeexplore.ieee.org/document/1424679) e de apresentações [1](https://cs.uwaterloo.ca/~dstinson/UNCC-Stinson.pdf) e [2](https://cs.uwaterloo.ca/~dstinson/papers/WLU.pdf).
* \[7\] [Bouncy Castle](https://www.bouncycastle.org/)
* \[8\] Joachim Gathen, CryptoSchool, Springer, 2015\.
* \[9\] [Enigma machine \- Wikipedia](https://en.wikipedia.org/wiki/Enigma_machine)
* \[10\] [Pollard's p − 1 algorithm \- Wikipedia](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm)
* \[11\] [Pollard's rho algorithm \- Wikipedia](https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm)
* \[12\] [Dixon's factorization method \- Wikipedia](https://en.wikipedia.org/wiki/Dixon%27s_factorization_method)
* \[13\] [Homomorphic encryption \- Wikipedia](https://en.wikipedia.org/wiki/Homomorphic_encryption)
* \[14\] [Awesome \- A curated list of amazing Homomorphic Encryption libraries, software and resources · GitHub](https://github.com/jonaschn/awesome-he)
* \[15\] [What is homomorphic encryption and how can it help in elections?](https://news.microsoft.com/on-the-issues/2020/04/13/what-is-homomorphic-encryption-and-how-can-it-help-in-elections/)
* \[16\] [Secret sharing \- Wikipedia](https://en.wikipedia.org/wiki/Secret_sharing)
* \[17\] [Shamir's secret sharing \- Wikipedia](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
* \[18\] [Study on Secret Sharing Schemes (SSS) and their applications | IEEE Conference Publication](https://ieeexplore.ieee.org/document/6148357)
* \[19\] [Threshold Schemes for Cryptographic Primitives](https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.8214.pdf)
* \[20\] [Secure searchable encryption: a survey | Journal of Communications and Information Networks | Springer Nature Link](https://link.springer.com/article/10.1007/BF03391580)
* \[21\] [Zero-Knowledge Proof (ZKP) — Explained | Chainlink](https://chain.link/education/zero-knowledge-proof-zkp)
* \[22\] [Zero-Knowledge Proof: Applications & Use Cases \- Chainlink](https://chain.link/education-hub/zero-knowledge-proof-use-cases)
* \[23\] [Exploring the Impact of Homomorphic Encryption on the Performance of Machine Learning Algorithms | Proceedings of the 12th Latin-American Symposium on Dependable and Secure Computing](https://dl.acm.org/doi/10.1145/3615366.3615376)
* \[24\] [https://eprint.iacr.org/2025/473.pdf](https://eprint.iacr.org/2025/473.pdf)
* \[25\] OWASP DevSecOps Guideline – [https://owasp.org/www-project-devsecops-guideline/](https://owasp.org/www-project-devsecops-guideline/)
* \[26\] GitLab DevSecOps Docs – https://docs.gitlab.com/ee/topics/devsecops/
* \[27\] Snyk Documentation – [https://docs.snyk.io/](https://docs.snyk.io/)
* \[28\] Trivy (Aqua Security) – [https://aquasecurity.github.io/trivy/](https://aquasecurity.github.io/trivy/)
* \[29\] HashiCorp Vault – [https://developer.hashicorp.com/vault/docs](https://developer.hashicorp.com/vault/docs)
* \[30\] Sigstore – https://sigstore.dev/
* \[31\] Open Policy Agent (OPA) – [https://www.openpolicyagent.org/](https://www.openpolicyagent.org/)