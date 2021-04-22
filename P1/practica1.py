'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging
import codecs

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60

def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	print("numero de paquetes leídos:")
	print(num_paquete)
	if handle:
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data): #es nuestro propio callback
	global num_paquete, pdumper
	num_paquete += 1
	logging.info('Nuevo paquete numero {} de {} bytes capturado a las {}.{}' .format(num_paquete,header.len,header.ts.tv_sec,header.ts.tv_sec))
	for i in range(args.nbytes):
		print(data[i:i+1].hex(), end=' ')

	print("\n")

	#Escribir el tráfico al fichero de captura con el offset temporal
	if args.interface:
		pcap_dump(pdumper, header, data)

	
if __name__ == "__main__":
	global pdumper,args,handle
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)
	
	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper = args.tracefile

	#TODO abrir la interfaz especificada para captura o la traza
	if args.interface:
		handle = pcap_open_live(args.interface, ETH_FRAME_MAX, 0, 100, errbuf) #1 Abrimos la interfaz
		if handle == None:
			logging.error('Error al capturar la interfaz')

		descr2 = pcap_open_dead(DLT_EN10MB, 1514) #Creamos el archivo donde volcar los paquetes
		pdumper = pcap_dump_open(descr2 , "captura" + str(int(time.time())) + args.interface + ".pcap") #dump es el archivo donde guardamos los paquetes
		if pdumper == None:
			logging.error('Error al guardar en el dumper')

	#TODO abrir un dumper ya existente para volcar el tráfico (si se ha especificado interfaz) (argumento --file)
	if args.tracefile:
		handle = pcap_open_offline(args.tracefile, errbuf) #Abre el archivo para lectura, luego se lee con pcap_loop
		if handle == None:
			logging.error('Error al abrir el archivo')

	ret = pcap_loop(handle, 50, procesa_paquete, None) #leemos el tráfico
	
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')

	logging.info('{} paquetes procesados'.format(num_paquete))

	if args.interface:
		pcap_close(descr2) #Cerramos el desc abierto con pcap_open_dead
		pcap_dump_close(pdumper)#Cerramos el desc abierto con pcap_dump_open

	pcap_close(handle) #Cerramos el desc abierto con pcap_openlive
