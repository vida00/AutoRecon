# AutoRecon
Script para auto recon, baseado no Smart-Recon da Desec Security, porém com algumas otimizações e fácil setup.

---
<br>

### Setup

```sh
> sudo apt install docker && sudo apt install docker-compose
> cd ~/ && git clone https://github.com/vida00/AutoRecon.git && mv AutoRecon recon && cd recon
> mkdir data-es && mkdir data && sudo chmod 777 -R data-es data
> docker build . && docker-compose up -d && sudo ./optimize.sh

Vídeo ensinando a usar o programa: 
```
