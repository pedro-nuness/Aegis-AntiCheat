<!-- Banner principal -->
<p align="center">
  <img src="https://img.shields.io/badge/AEGIS-ANTICHEAT-1f1f1f?style=for-the-badge&logo=shield&logoColor=white" alt="AEGIS AntiCheat Logo">
</p>

<h1 align="center">🛡️ AEGIS-ANTICHEAT</h1>
<p align="center">
  <em>Proteção avançada para jogos — desenvolvido para manter seu servidor DayZ livre de trapaças e modificações não autorizadas.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/github/license/pedro-nuness/Aegis-AntiCheat?style=flat-square">
  <img src="https://img.shields.io/github/last-commit/pedro-nuness/Aegis-AntiCheat?style=flat-square">
  <img src="https://img.shields.io/github/stars/pedro-nuness/Aegis-AntiCheat?style=flat-square">
  <img src="https://img.shields.io/github/issues/pedro-nuness/Aegis-AntiCheat?style=flat-square">
</p>

---

<div style="display:flex; flex-direction:row; align-items:center; justify-content:center;">
  <img src="https://raw.githubusercontent.com/pedro-nuness/Aegis-AntiCheat/refs/heads/main/AEGIS.jpg" style="width:400px;">
  <img src="https://raw.githubusercontent.com/pedro-nuness/Aegis-AntiCheat/refs/heads/main/AEGIS2.jpg" style="width:400px;">
  <img src="https://raw.githubusercontent.com/pedro-nuness/Aegis-AntiCheat/refs/heads/main/AEGIS3.jpg" style="width:400px;">
</div>


---

## 🚀 Tecnologias Utilizadas

<p align="center">
  <img src="https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=cplusplus&logoColor=white">
  <img src="https://img.shields.io/badge/MinHook-1f1f1f?style=for-the-badge&logo=windows&logoColor=white">
  <img src="https://img.shields.io/badge/WinDivert-1f1f1f?style=for-the-badge">
  <img src="https://img.shields.io/badge/OpenSSL-721412?style=for-the-badge&logo=openssl&logoColor=white">
  <img src="https://img.shields.io/badge/cURL-073551?style=for-the-badge&logo=curl&logoColor=white">
  <img src="https://img.shields.io/badge/D++-1f1f1f?style=for-the-badge&logo=discord&logoColor=white">
  <img src="https://img.shields.io/badge/nlohmann/json-1f1f1f?style=for-the-badge&logo=json&logoColor=white">
</p>

---

## 📜 Sobre o Projeto

O **AEGIS-ANTICHEAT** é um sistema de segurança robusto, construído em C++ e projetado para proteger jogos contra cheaters.  
Ele utiliza uma arquitetura **cliente-servidor** com técnicas avançadas de injeção, hooking e monitoramento, detectando e prevenindo atividades maliciosas em tempo real.

💡 **Principais destaques**:
- 🖥️ **Injeção Manual de DLL** (Manual Mapping) para furtividade.
- 🔐 **Comunicação Criptografada** com AES-256.
- 🎯 **Detecção de Processos, Drivers e Debuggers**.
- 📡 **Interceptação de Pacotes** via WinDivert.
- 📲 **Integração com Discord** para alertas instantâneos.

---


## 📂 Estrutura do Projeto

```bash
Aegis-AntiCheat/
├── AegisStarter           # Lançador e injeção de DLL
├── AntiCheat              # Núcleo do anticheat
├── AntiCheatProtector     # Variação com proteção extra
├── ProcessDumper          # Ferramenta de monitoramento
├── LogDecryptor           # Descriptografia de logs
├── server                 # Servidor de autenticação e bans
├── headerGenerator        # Conversão binário → array
├── InternalCheatExample   # Exemplo interno de cheat
├── ExternalCheatExample   # Exemplo externo de cheat
└── README.md
```

---

## 🛠️ Instalação

> ⚠️ Pré-requisitos:
> - **Windows 10/11**
> - **Visual Studio 2022** com C++ Desktop Development
> - **Windows SDK 10**
> - vcpkg (opcional, para dependências)

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/Aegis-AntiCheat.git
cd Aegis-AntiCheat

# 2. Compile a solução
# Abra o AegisAnticheat.sln no Visual Studio e compile em modo Release

# 3. Configure o servidor
# Edite server/config/config.json com as suas chaves e portas
```

