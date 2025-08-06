# Aegis Anti-Cheat

## Visão Geral

O Aegis Anti-Cheat é uma solução de anti-cheat em desenvolvimento, inicialmente concebida para o jogo DayZ. O projeto visa fornecer uma plataforma robusta e multifacetada para detectar e prevenir trapaças em jogos online, combinando componentes de modo de usuário (user-mode) e modo kernel (kernel-mode) para uma proteção abrangente.

Este projeto nasceu da necessidade de criar um ambiente de jogo mais justo e seguro, combatendo uma variedade de métodos de trapaça, desde simples exploits até cheats mais complexos que operam em níveis mais baixos do sistema operacional.

## Arquitetura do Projeto

O Aegis é composto por vários módulos que trabalham em conjunto para proteger o ambiente do jogo:

-   **`AntiCheat/`**: O componente principal do lado do cliente, responsável pela maior parte da detecção de trapaças em user-mode.
-   **`Driver/`**: Um driver de modo kernel que oferece recursos avançados de detecção e proteção, operando com privilégios elevados para monitorar o sistema de forma eficaz.
-   **`server/`**: O componente de back-end que gerencia a autenticação do cliente, recebe dados, processa detecções e gerencia configurações como whitelists.
-   **`AegisStarter/`**: Um launcher para o jogo que garante que o anti-cheat seja carregado corretamente antes da execução do processo principal do jogo.
-   **`AntiCheatProtector/`**: Um módulo dedicado a proteger os processos do próprio anti-cheat contra-ataques e finalização.

### Ferramentas e Exemplos

O projeto também inclui várias ferramentas e exemplos para desenvolvimento e teste:

-   **`ProcessDumper/`**: Uma ferramenta para extrair a memória de um processo para análise.
-   **`LogDecryptor/`**: Utilitário para descriptografar os logs gerados pelo anti-cheat.
-   **`InternalCheatExample/` & `ExternalCheatExample/`**: Exemplos de cheats internos e externos, usados para testar a eficácia das detecções do Aegis.

## Funcionalidades (Planejadas e Implementadas)

-   **Análise de Memória**: Varredura da memória do processo do jogo em busca de assinaturas de cheats conhecidos, modificações de código e padrões suspeitos.
-   **Proteção de Processo**: Impede que outros processos acessem ou manipulem a memória do jogo e do anti-cheat.
-   **Validação de Módulos**: Verifica a integridade dos módulos carregados no processo do jogo.
-   **Detecção via Driver**: Utiliza o driver de kernel para monitorar chamadas de sistema (syscalls), acesso a handles e outras atividades de baixo nível.
-   **Comunicação Segura**: Comunicação criptografada entre o cliente e o servidor para garantir a integridade dos dados.
-   **Sistema de Heartbeat**: Verificações periódicas para garantir que o cliente anti-cheat está ativo e não foi adulterado.

## Como Compilar

1.  Abra a solução `AegisAnticheat.sln` no Visual Studio.
2.  Certifique-se de ter o Windows Driver Kit (WDK) instalado para compilar o projeto `Driver/`.
3.  Configure as dependências e bibliotecas externas conforme necessário para cada projeto.
4.  Compile a solução na configuração desejada (Debug ou Release) para a arquitetura x64.

## Status do Projeto

Este projeto está em desenvolvimento ativo. Nem todas as funcionalidades podem estar completas ou estáveis.

**AVISO**: Este software lida com operações de baixo nível e inclui um driver de kernel. Use-o com responsabilidade e por sua conta e risco. A instalação de drivers não assinados ou instáveis pode causar instabilidade no sistema (BSOD).

## Contribuições

Contribuições são bem-vindas. Sinta-se à vontade para abrir uma *issue* para relatar bugs ou sugerir novas funcionalidades.

## Funcionamento Técnico Detalhado

O Aegis Anti-Cheat é composto por múltiplos módulos que atuam em camadas distintas do sistema operacional, integrando técnicas avançadas de detecção, proteção, comunicação e resposta a ameaças. Veja como cada parte atua:

### Fluxo Geral
- O **AegisStarter** garante que o anti-cheat e o driver estejam carregados antes do jogo iniciar.
- O **AntiCheat** (user-mode) é injetado no processo do jogo, monitorando memória, módulos, janelas e processos suspeitos.
- O **Driver** (kernel-mode) oferece monitoramento de baixo nível, protegendo processos e detectando manipulações avançadas.
- O **AntiCheatProtector** atua como watchdog, protegendo o anti-cheat contra finalização, injeção ou manipulação.
- O **servidor** recebe logs, eventos e heartbeats dos clientes, processa detecções e aplica políticas (banimentos, whitelists, etc).

### Detecção e Monitoramento
- **Varredura de Módulos:** Mantém um banco de dados de módulos legítimos. Ao detectar um módulo desconhecido ou modificado, coleta informações, envia ao servidor e pode acionar alertas.
- **Detecção de Hooks:** Verifica hooks em funções críticas (IAT/EAT), detectando alterações em ponteiros de função e instruções suspeitas.
- **Análise de Threads:** Monitora threads injetadas, threads suspensas e alterações incomuns no fluxo de execução do processo do jogo.
- **Monitoramento de Janelas e Processos:** Detecta overlays, debuggers, injetores e ferramentas de cheat conhecidas, inclusive por nomes, classes de janela e assinaturas de memória.
- **Proteção de Integridade:** Valida a integridade de arquivos, módulos e regiões de memória, detectando alterações ou injeções.
- **Verificação de Handles:** Identifica processos que possuem handles perigosos abertos para o jogo ou para o anti-cheat, bloqueando ou reportando tentativas de manipulação.

### Comunicação Segura
- Comunicação entre cliente e servidor via sockets TCP, utilizando criptografia AES-256.
- O cliente envia periodicamente heartbeats, logs de detecção e eventos suspeitos.
- O servidor pode responder com comandos, atualizações de políticas e whitelists.
- Em caso de falha de comunicação, o cliente tenta reconectar automaticamente, com múltiplas tentativas e logs de erro.

### Logs e Auditoria
- Módulo de logging robusto (`LogSystem`), que registra eventos locais e remotos.
- Logs são criptografados e podem ser descriptografados com a ferramenta LogDecryptor.
- Eventos críticos (detecções, falhas de integridade, tentativas de manipulação) são enviados ao servidor para auditoria centralizada.

### Proteção e Autodefesa
- O **AntiCheatProtector** monitora tentativas de finalização, injeção de código e manipulação do anti-cheat, reiniciando ou bloqueando ações suspeitas.
- Técnicas de obfuscação e anti-tamper dificultam engenharia reversa e ataques ao próprio anti-cheat.
- O driver de kernel impede acesso não autorizado ao processo do jogo e ao anti-cheat, protegendo contra cheats em kernel-mode.

### Integração, Testes e Ferramentas
- Exemplos de cheats internos e externos são usados para validar a eficácia das detecções.
- Ferramentas como ProcessDumper permitem análise forense de processos suspeitos.
- O sistema é modular, permitindo fácil atualização de regras, assinaturas e políticas via servidor.

### Fluxo de Banimento e Whitelist
- O servidor mantém listas de banimento por HWID, disco, BIOS, MAC e SteamID.
- Whitelists podem ser atualizadas em tempo real, permitindo exceções para desenvolvedores ou testers.

### Atualização e Resposta Rápida
- O sistema pode ser atualizado automaticamente, sem intervenção do usuário, garantindo resposta rápida a novas ameaças.

---

Essas camadas e fluxos trabalham em conjunto para criar um ambiente hostil a trapaças, dificultando tanto ataques em user-mode quanto em kernel-mode, e permitindo resposta rápida a novas ameaças por meio do backend centralizado.

## Bibliotecas Utilizadas

O projeto Aegis Anti-Cheat faz uso de diversas bibliotecas e dependências para implementar suas funcionalidades. Abaixo estão algumas das principais bibliotecas utilizadas em diferentes módulos do projeto:

### AntiCheat/
- **Windows API**: Utilizada extensivamente para manipulação de processos, memória, janelas e módulos.
- **WinSock**: Para comunicação de rede entre cliente e servidor.
- **CryptoAPI**: Para operações de criptografia e hashing.
- **Zlib**: Compressão e descompressão de dados.
- **JSON for Modern C++ (nlohmann/json)**: Manipulação de arquivos e comunicação em JSON.

### Driver/
- **Windows Driver Kit (WDK)**: Base para desenvolvimento do driver em modo kernel.
- **KMDF/UMDF**: Frameworks de driver do Windows para abstração e simplificação do desenvolvimento.

### server/
- **Boost.Asio**: Biblioteca para comunicação de rede assíncrona.
- **nlohmann/json**: Manipulação de dados em JSON.
- **OpenSSL**: Criptografia e segurança na comunicação.

### Ferramentas e utilitários
- **MinHook**: Biblioteca para hooking de funções em user-mode.
- **EasyHook**: Alternativa para injeção e manipulação de funções.
- **spdlog**: Logging rápido e eficiente.
- **fmt**: Formatação de strings moderna e segura.
