# Shoxz Desobfuscador — versão nova

Bot Discord com interface de análise estática. Use `/analisar` e anexe uma DLL. O bot envia um embed organizado com:

- nome e tamanho do arquivo;
- SHA-256;
- domínios e URLs HTTPS;
- possíveis Photon App IDs em formato UUID;
- referências a backend/Photon;
- relatório de texto anexado.

O botão **Mais...** abre uma segunda visão com informações aprofundadas: assinatura PE, arquitetura, número e nomes de seções, timestamp, entropia, indicação de .NET/CLR, URLs, Photon IDs e referências detectadas. O bot não ataca Photon, servidores, jogadores ou redes e não executa código recebido.

## Instalação

```bash
python -m pip install -r requirements.txt
```

Ative **Message Content Intent** no Discord Developer Portal e convide o bot com `bot` e `applications.commands`, além de permissões para visualizar canais, enviar mensagens, incorporar links e anexar arquivos.

Configure o token sem colocá-lo no arquivo:

```bat
set DISCORD_BOT_TOKEN=SEU_TOKEN_NOVO
python bot.py
```

Opcionalmente, defina `DISCORD_GUILD_ID` com o ID do seu servidor para sincronizar `/analisar` imediatamente nesse servidor. Sem essa variável, o bot usa sincronização global do Discord, que pode demorar alguns minutos.

O limite é 25 MB por DLL. O código externo indicado não é baixado nem executado.

O pacote inclui `Dockerfile` e `.env.example`. Nunca inclua o token real no ZIP, no código ou em um repositório público.
