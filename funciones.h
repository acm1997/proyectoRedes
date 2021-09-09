#include <stdio.h>
#include <stdio_ext.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include "linkLayer.h"
#include "tramas.h"

using namespace std;

//============================================================================
// ----------- PRACTICAS DE FUNDAMENTOS DE REDES DE COMUNICACIONES -----------
// ---------------------------- CURSO 2020/21 --------------------------------
// ----------------------------- FUNCIONES.H ---------------------------------
// ---------------- ABEL GONZALO BARBA Y ANGEL CAÑADA MUÑOZ ------------------
//============================================================================


/*********** CONSTANTES **********/
const unsigned char ESC = 27;
const unsigned char caracter2 = 'O';
const unsigned char F1 = 'P';
const unsigned char F2 = 'Q';
const unsigned char F3 = 'R';
const unsigned char F4 = 'S';


/************* MENUS *************/
void cabecera();
void mostrarInterfaces(pcap_if_t *avail_ifaces);
void seleccionarInterfaz(pcap_if_t *avail_ifaces, interface_t &iface);
int elegirGrupo();

/*
* Método que define el comportamiento de la estacion (maestra o esclava).
*/
void elegirMaestroEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *type);

/*
* Método para elegir la funcionalidad a realizar en la estacion MAESTRA (envio caracter o envio de fichero).
*/
void elegirModoEnvioMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);

/*
* Método para elegir la funcionalidad a realizar en la estacion ESCLAVA (envio caracter ).
*/
void elegirModoEnvioEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);


/*********** FUNCIONES ***********/

/*
* Método que envia un caracter en el modo interactivo.
*/
void EnviarCaracter(interface_t iface, unsigned char *mac_src,
                    unsigned char *mac_dst, unsigned char *type, unsigned char tecla);

/*
* Método que se encarga de enviar la trama inicial del maestro mediante comunicación broadcast.
*/
void descubrimientoMaestro(interface_t iface, unsigned char *mac_src,unsigned char *broadcast, unsigned char *type);


/*
* Método que se encarga de enviar la trama inicial del esclavo (tras el descubrimiento) a la estacion maestra.
*/
void descubrimientoEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst,unsigned char *type);

/*
* Método que se encarga de leer el fichero de entrada y enviar el contenido de este.
*/
void enviarFichero(interface_t iface,  unsigned char *mac_dst, unsigned char *type);

/*
* Método que se encarga de enviar una trama con los últimos caracteres leídos.
*/
void enviarTramaFichero(interface_t iface,  unsigned char *mac_dst, unsigned char *type, unsigned char *cadena, int tamanoTrama);

void protocoloMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);
void protocoloEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);

/*SELECCION*/
void establecimientoSeleccion(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);
void transferencia (interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, unsigned char operacion);

void esperaProtocoloMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);
void esperaProtocoloEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);

/*SONDEO*/
void establecimientoSondeo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);
void recibirFicheroMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);

void esperaEOTMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, char nTrama); 
void solicitarCierreProtocolo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, unsigned char op, char nTrama);


/*********** PRINCIPAL ***********/
void enviar(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, unsigned char &tecla);
void recibir(interface_t iface, unsigned char *type);

/*
* Método que se encarga de enviar y recibir los caracteres de manera interactiva en ambas estaciones.
*/
void buclePrincipal(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type);