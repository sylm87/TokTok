#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = "SYLM"
__credits__ = ["SYLM","Roadmaster","RecursosPython.com"]
__license__ = "GPLv3"
__version__ = "0.1"
__maintainer__ = "$y/_M"
__email__ = "christian472006@gmail.com"
__status__ = "Development"

import requests  # Necesita instalarse (por ejemplo mediante pip: "pip install requests" )
import forcediphttpsadapter.adapters # https://github.com/Roadmaster/forcediphttpsadapter (By Roadmaster)
from urllib.parse import urlparse
import hashlib
import os
import argparse
import socket
import ipaddress


fake_vhosts = ["fakehost.fakenow", "notexist.vhostinvalid", "notval.fkhs"]
user_agent = "Mozilla/5.0"
requests.packages.urllib3.disable_warnings()



def find_vhost(ip_host, url_searched, fake=False, fake_domain=""):

    url_parsed = urlparse(url_searched)
    protocol = url_parsed[0]
    vhost = url_parsed[1].split(":")[0]
    url_path = url_parsed[2]
    parameters = url_parsed[3]

    if fake:
        print("COMPROBANDO FALSO POSITIVO -> " + fake_domain + " -> ", end="")
    else:
        print ("Buscando virtualhost " + vhost + " en la IP " + ip_host + " -> ", end="")

    # Preparamos los headers de las peticiones
    headers = {'Host': str(vhost), 'User-Agent': user_agent}

    try:

        if protocol == "https":
            session = requests.Session()
            session.mount(url_searched, forcediphttpsadapter.adapters.ForcedIPHTTPSAdapter(dest_ip=ip_host))
            response = session.get(url_searched, headers=headers, verify=False, allow_redirects=False, timeout=3)
        else:
            url_searched = url_searched.replace(vhost,ip_host)
            response = requests.get(url_searched, headers=headers, allow_redirects=False, timeout=3)


        if response.status_code == (301 or 302):

            if ((str(response.headers["Location"]).find(str(vhost)) != -1) or (str(response.headers["Location"])[0] == "/")) and fake == False:
                print(" POSIBLEMENTE LOCALIZADO (REDIRECT TO ->" + response.headers["Location"] + ")")
            else:
                print ("FAIL! (REDIRECCIÓN A -> " + response.headers["Location"] + ")")

            return ["3XX"]

        elif response.status_code == 200:

            if not fake:
                orig_hash = hashlib.new("sha256", response.text.encode('utf-8'))
                print("LOCALIZADO! (200 OK)")
                print("HASH dominio original -> " + orig_hash.hexdigest())
                contador_positivos = 0
                lista_hashes = []
                for fake_vhost in fake_vhosts:
                    resultado = find_vhost(ip_host, protocol + "://" + fake_vhost + url_path, fake=True, fake_domain=fake_vhost)
                    if resultado[0] == "200":
                        hash = hashlib.new("sha256", resultado[1].encode('utf-8'))
                        lista_hashes.append(hash)
                        print(hash.hexdigest())
                        if orig_hash.hexdigest() == hash.hexdigest():
                            contador_positivos += 1
                if contador_positivos > 0:
                    print(" ** POSIBLE FALSO POSITIVO, CUIDADO! :-S **")
                else:
                    print(" ##############################################")
                    print(" ## PARECE QUE HEMOS CONFIRMADO DOMINIO! :-) ##")
                    print(" ##############################################")

                return ["200"]
            else:
                return["200", response.text]

        elif response.status_code == 400:
            print("FAIL!")
            return ["400"]

        else:
            print("FAIL!")
            return ["XXX"]

    except Exception as e:
        print ("FAIL (ERROR DESCONOCIDO)")
        #print (e)
        return ["FFF"]

def clear(): # By RECURSOSPYTHON.COM
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def banner():
    print("""
 _____     _    _____     _    _ 
|_   _|__ | | _|_   _|__ | | _| |
  | |/ _ \| |/ / | |/ _ \| |/ / |            you?
  | | (_) |   < B| |Y(_) |   <|_|  Where    
  |_|\_S_/|_|\Y\ |_|\_L_/|_|\M(_)        are
                                        
    """)

# Parseo de argumentos
parser = argparse.ArgumentParser(description='Finding hidden virtualhost (after DNS gathering). Protected with WAFs such as Cloudfare, Akamai, Incapsula...')
parser.add_argument("-u", "--url", dest="url",help="URL completa necesaria para la búsqueda del host virtual.",nargs=1, required=True)
parser.add_argument("-fh","--filehosts",dest="filehosts",help="Fichero que contiene las IP de los hosts donde se buscarán los virtual host.", nargs = 1, required=True)
args = parser.parse_args()





if __name__ == '__main__':

    #clear()
    banner()

    web = args.url[0]
    filename_hosts = args.filehosts[0]
    IP_list = []
    try:
        check_url = urlparse(web)
        with open(filename_hosts) as fhosts:
            for line in fhosts:
                host = line.strip()
                try:
                    for ip in ipaddress.IPv4Network(host):
                    	IP_list.append(str(ip))
                    #print(IP_list)
                    #socket.inet_aton(host)
                    #IP_list.append(host)
                except:
                    pass
    except Exception as e:
        print(e)
        exit(1)

    if len(IP_list) > 0:
        mensaje_busqueda_vhost = "Buscando: " + web.upper()
        print(mensaje_busqueda_vhost)
        print("=" * len(mensaje_busqueda_vhost))
        for ip in IP_list:
            find_vhost(ip, web)
        exit(0)
    else:
        print("EY! El fichero de direcciones está vacío o contiene direcciones IP mal formadas, revísalo.")
        exit(1)

