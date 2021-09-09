#include <stdio.h>
#include <stdio_ext.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include "linkLayer.h"

using namespace std;

//============================================================================
// ----------- PRACTICAS DE FUNDAMENTOS DE REDES DE COMUNICACIONES -----------
// ---------------------------- CURSO 2020/21 --------------------------------
// ----------------------------- FUNCIONES.H ---------------------------------
// ---------------- ABEL GONZALO BARBA Y ANGEL CAÑADA MUÑOZ ------------------
//============================================================================



/*********** CONSTANTES **********/
const int ENQ = 05;
const int EOT = 04;
const int ACK = 06;
const int NACK = 21;
const int STX = 02;



/*********** FUNCIONES ***********/
unsigned char *crearTramaControl(char direccion, int control, char nTrama);
unsigned char *crearTramaDatos(unsigned char direccion, int control, char nTrama, unsigned char *datos,int tamano);
unsigned char calcularBCE(unsigned char *datos);