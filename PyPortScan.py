#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════╗
║           PyPortScan - Port Scanner           ║
║     Ferramenta de varredura de portas TCP      ║
╚═══════════════════════════════════════════════╝

Uso:
  python port_scanner.py <alvo> [opções]

Exemplos:
  python port_scanner.py 192.168.1.1
  python port_scanner.py scanme.nmap.org -p 1-1000
  python port_scanner.py 10.0.0.1 -p 22,80,443,8080 -t 100 -o resultado.txt

Autor: Guilherme Valentino de Castro
"""

import socket
import threading
import argparse
import sys
import os
import json
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed


# ──────────────────────────── Cores ANSI ────────────────────────────

class Cor:
    RESET  = "\033[0m"
    VERDE  = "\033[92m"
    VERM   = "\033[91m"
    AZUL   = "\033[94m"
    AMARELO= "\033[93m"
    CINZA  = "\033[90m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"

    @staticmethod
    def suporte() -> bool:
        """Verifica se o terminal suporta cores."""
        return sys.stdout.isatty() and os.name != "nt" or (
            os.name == "nt" and os.system("") == 0
        )


# ──────────────────────── Serviços conhecidos ────────────────────────

SERVICOS = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
    119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP Trap", 179: "BGP", 194: "IRC", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    515: "LPD", 587: "SMTP", 631: "IPP", 636: "LDAPS",
    873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL",
    2181: "ZooKeeper", 2375: "Docker", 2376: "Docker TLS",
    3000: "Dev Server", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4000: "Dev Server", 5000: "Flask/Dev", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic",
    8000: "HTTP Alt", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
    8888: "Jupyter", 9000: "SonarQube", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "Elasticsearch", 27017: "MongoDB",
}


# ────────────────────────── Banner Grabber ───────────────────────────

def capturar_banner(ip: str, porta: int, timeout: float = 1.5) -> str:
    """Tenta capturar o banner de serviço de uma porta aberta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, porta))
            # Envia requisição HTTP genérica para portas web
            if porta in (80, 8080, 8000, 8888):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # Retorna apenas a primeira linha não vazia
            for linha in banner.splitlines():
                linha = linha.strip()
                if linha:
                    return linha[:80]
    except Exception:
        pass
    return ""


# ──────────────────────────── Scanner ────────────────────────────────

class PortScanner:
    def __init__(self, alvo: str, portas: list[int], threads: int = 200,
                 timeout: float = 1.0, banner: bool = False):
        self.alvo    = alvo
        self.ip      = self._resolver_ip(alvo)
        self.portas  = portas
        self.threads = min(threads, len(portas), 500)
        self.timeout = timeout
        self.banner  = banner
        self.abertas: list[dict] = []
        self._lock   = threading.Lock()

    @staticmethod
    def _resolver_ip(alvo: str) -> str:
        try:
            return socket.gethostbyname(alvo)
        except socket.gaierror:
            print(f"{Cor.VERM}[ERRO] Não foi possível resolver o host: {alvo}{Cor.RESET}")
            sys.exit(1)

    def _escanear_porta(self, porta: int) -> dict | None:
        """Testa se uma porta está aberta. Retorna dict com dados ou None."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                resultado = s.connect_ex((self.ip, porta))
                if resultado == 0:
                    servico = SERVICOS.get(porta, "Desconhecido")
                    banner  = self.capturar_banner_porta(porta) if self.banner else ""
                    return {"porta": porta, "servico": servico, "banner": banner}
        except Exception:
            pass
        return None

    def capturar_banner_porta(self, porta: int) -> str:
        return capturar_banner(self.ip, porta, self.timeout + 0.5)

    def executar(self, callback=None) -> list[dict]:
        """Executa o scan com ThreadPoolExecutor."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futuros = {executor.submit(self._escanear_porta, p): p for p in self.portas}
            for futuro in as_completed(futuros):
                resultado = futuro.result()
                if resultado:
                    with self._lock:
                        self.abertas.append(resultado)
                    if callback:
                        callback(resultado)

        self.abertas.sort(key=lambda x: x["porta"])
        return self.abertas


# ──────────────────────────── Parser ─────────────────────────────────

def parse_portas(texto: str) -> list[int]:
    """
    Converte string de portas em lista de inteiros.
    Aceita: '80', '22,80,443', '1-1024', '22,80,1000-2000'
    """
    portas = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fim = parte.split("-", 1)
            portas.update(range(int(inicio), int(fim) + 1))
        else:
            portas.add(int(parte))
    return sorted(p for p in portas if 1 <= p <= 65535)


# ───────────────────────────── CLI ───────────────────────────────────

BANNER_ARTE = f"""{Cor.CYAN}{Cor.BOLD}
  ██████╗ ██╗   ██╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██████╔╝ ╚████╔╝ ██████╔╝██║   ██║██████╔╝   ██║   
  ██╔═══╝   ╚██╔╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║   
  ██║        ██║   ██║     ╚██████╔╝██║  ██║   ██║   
  ╚═╝        ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
        ███████╗ ██████╗ █████╗ ███╗   ██╗
        ██╔════╝██╔════╝██╔══██╗████╗  ██║
        ███████╗██║     ███████║██╔██╗ ██║
        ╚════██║██║     ██╔══██║██║╚██╗██║
        ███████║╚██████╗██║  ██║██║ ╚████║
        ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Cor.RESET}"""


def criar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="PyPortScan — Varredura de portas TCP com Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python port_scanner.py scanme.nmap.org
  python port_scanner.py 192.168.1.1 -p 1-1024
  python port_scanner.py 10.0.0.1 -p 22,80,443 --banner -o saida.json
  python port_scanner.py meusite.com -p top100 -t 300
        """
    )
    parser.add_argument("alvo", help="IP ou hostname do alvo")
    parser.add_argument(
        "-p", "--portas",
        default="1-1024",
        help="Portas a escanear: '80', '22,80,443', '1-65535', 'top100' (padrão: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int, default=200,
        help="Número de threads simultâneas (padrão: 200)"
    )
    parser.add_argument(
        "--timeout",
        type=float, default=1.0,
        help="Timeout por porta em segundos (padrão: 1.0)"
    )
    parser.add_argument(
        "--banner",
        action="store_true",
        help="Tenta capturar banner dos serviços"
    )
    parser.add_argument(
        "-o", "--output",
        help="Salvar resultado em arquivo (.txt ou .json)"
    )
    parser.add_argument(
        "--sem-cor",
        action="store_true",
        help="Desativa cores no terminal"
    )
    return parser


TOP_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123, 135, 139, 143, 161, 194,
    389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 993, 995, 1080, 1194,
    1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3306, 3389,
    3690, 4000, 5000, 5432, 5900, 6379, 6443, 7001, 8000, 8080, 8443, 8888,
    9000, 9090, 9200, 9300, 27017,
]


def main():
    parser = criar_parser()
    args   = parser.parse_args()

    # Desativa cores se pedido ou sem suporte
    if args.sem_cor or not Cor.suporte():
        for attr in vars(Cor):
            if not attr.startswith("_") and isinstance(getattr(Cor, attr), str):
                setattr(Cor, attr, "")

    print(BANNER_ARTE)

    # Resolve portas
    if args.portas.lower() == "top100":
        portas = TOP_100
    elif args.portas == "all":
        portas = list(range(1, 65536))
    else:
        try:
            portas = parse_portas(args.portas)
        except ValueError:
            print(f"{Cor.VERM}[ERRO] Formato de portas inválido: {args.portas}{Cor.RESET}")
            sys.exit(1)

    inicio = datetime.now()

    print(f"{Cor.BOLD}{'─'*55}{Cor.RESET}")
    print(f"  {Cor.AZUL}Alvo       :{Cor.RESET} {args.alvo}")
    print(f"  {Cor.AZUL}IP         :{Cor.RESET} {socket.gethostbyname(args.alvo)}")
    print(f"  {Cor.AZUL}Portas     :{Cor.RESET} {len(portas)} porta(s)")
    print(f"  {Cor.AZUL}Threads    :{Cor.RESET} {args.threads}")
    print(f"  {Cor.AZUL}Timeout    :{Cor.RESET} {args.timeout}s")
    print(f"  {Cor.AZUL}Banner     :{Cor.RESET} {'Sim' if args.banner else 'Não'}")
    print(f"  {Cor.AZUL}Início     :{Cor.RESET} {inicio.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Cor.BOLD}{'─'*55}{Cor.RESET}\n")

    print(f"  {Cor.AMARELO}Escaneando...{Cor.RESET}\n")

    scanner = PortScanner(
        alvo=args.alvo,
        portas=portas,
        threads=args.threads,
        timeout=args.timeout,
        banner=args.banner,
    )

    resultados_live = []

    def ao_encontrar(r):
        banner_txt = f"  {Cor.CINZA}↳ {r['banner']}{Cor.RESET}" if r["banner"] else ""
        linha = (
            f"  {Cor.VERDE}[ABERTA]{Cor.RESET}  "
            f"{Cor.BOLD}{r['porta']:>5}/tcp{Cor.RESET}  "
            f"{Cor.CYAN}{r['servico']:<18}{Cor.RESET}"
        )
        print(linha)
        if banner_txt:
            print(banner_txt)
        resultados_live.append(r)

    abertas = scanner.executar(callback=ao_encontrar)
    fim     = datetime.now()
    duracao = (fim - inicio).total_seconds()

    print(f"\n{Cor.BOLD}{'─'*55}{Cor.RESET}")
    print(f"  {Cor.VERDE if abertas else Cor.VERM}{len(abertas)} porta(s) aberta(s){Cor.RESET} "
          f"em {duracao:.2f}s")
    print(f"  Concluído em {fim.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Cor.BOLD}{'─'*55}{Cor.RESET}\n")

    # Exportar resultado
    if args.output:
        salvar_resultado(args.output, args.alvo, scanner.ip, abertas, inicio, fim)
        print(f"  {Cor.AMARELO}Resultado salvo em: {args.output}{Cor.RESET}\n")


def salvar_resultado(caminho: str, alvo: str, ip: str,
                     abertas: list[dict], inicio: datetime, fim: datetime):
    """Salva o resultado em .txt ou .json."""
    ext = os.path.splitext(caminho)[1].lower()

    if ext == ".json":
        dados = {
            "alvo": alvo,
            "ip": ip,
            "inicio": inicio.isoformat(),
            "fim": fim.isoformat(),
            "duracao_segundos": (fim - inicio).total_seconds(),
            "portas_abertas": abertas,
        }
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
    else:
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(f"PyPortScan — Resultado do Scan\n")
            f.write(f"{'='*45}\n")
            f.write(f"Alvo    : {alvo} ({ip})\n")
            f.write(f"Início  : {inicio.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Fim     : {fim.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duração : {(fim - inicio).total_seconds():.2f}s\n")
            f.write(f"{'='*45}\n\n")
            f.write(f"{'PORTA':<8} {'SERVIÇO':<20} {'BANNER'}\n")
            f.write(f"{'-'*60}\n")
            for r in abertas:
                f.write(f"{r['porta']:<8} {r['servico']:<20} {r['banner']}\n")
            f.write(f"\n{len(abertas)} porta(s) aberta(s) encontrada(s).\n")


if __name__ == "__main__":
    main()
