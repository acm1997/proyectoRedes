#include "tramas.h"

//============================================================================
// ----------- PRACTICAS DE FUNDAMENTOS DE REDES DE COMUNICACIONES -----------
// ---------------------------- CURSO 2020/21 --------------------------------
// ----------------------------- FUNCIONES.CPP -------------------------------
// ---------------- ABEL GONZALO BARBA Y ANGEL CAÑADA MUÑOZ ------------------
//============================================================================

unsigned char *crearTramaControl(char direccion, int control, char nTrama)
{
    unsigned char *tramaControl = (unsigned char *)malloc(3 * sizeof(unsigned char));

    tramaControl[0] = direccion;
    tramaControl[1] = (unsigned char)control;
    tramaControl[2] = nTrama;
    
    return tramaControl;
}

unsigned char *crearTramaDatos(unsigned char direccion, int control, char nTrama, unsigned char *datos, int tamano)
{
    unsigned char *tramaDatos = (unsigned char *)malloc((tamano+5) * sizeof(unsigned char));

    tramaDatos[0] = direccion;
    tramaDatos[1] = (unsigned char)control; 
    tramaDatos[2] = (unsigned char)nTrama;
    tramaDatos[3] = (unsigned char) tamano;


    int i;
    for (i = 4; datos[i-4] != '\0'; i++)
    {
        tramaDatos[i] = datos[i - 4];
       // cout<<tramaDatos[i];

    }
    tramaDatos[i] = calcularBCE(datos);

    cout<<endl;
    //cout<< "BCE: "<< (int) tramaDatos[i]<<endl;

    i = 0;

    return tramaDatos;
}

unsigned char calcularBCE(unsigned char *datos)
{
    unsigned char bce = datos[0];
    //strlen
    for (int i = 1; datos[i] != '\0' && i < (strlen((char *) datos)); i++) { //Mientras que no estemos en el final de la cadena de datos
		bce ^= datos[i]; //Te hace XOR de todas las posiciones.
	}

	return bce;
}