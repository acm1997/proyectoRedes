//============================================================================
// ----------- PRACTICAS DE FUNDAMENTOS DE REDES DE COMUNICACIONES -----------
// ---------------------------- CURSO 2020/21 --------------------------------
// ----------------------------- SESION1.CPP ---------------------------------
// ---------------- ABEL GONZALO BARBA Y ANGEL CAÑADA MUÑOZ ------------------
//============================================================================

#include <stdio.h>
#include <stdio_ext.h>
#include <iostream>
#include "linkLayer.h"
#include "funciones.h"

using namespace std;

int main()
{
    interface_t iface;
    pcap_if_t *avail_ifaces = NULL;
    int Puerto;

    /*
    *Configurar origen, destino y tipo
    */

    //MAC Destino (Angel)
    unsigned char mac_dst[6] = {0x08, 0x00, 0x27, 0x10, 0x38, 0x9d};
    unsigned char type[2] = {0x30, 0x00};

    cabecera();
    mostrarInterfaces(avail_ifaces);
    seleccionarInterfaz(avail_ifaces, iface);

    //MAC Origen
    unsigned char mac_src[6] = {iface.MACaddr[0], iface.MACaddr[1], iface.MACaddr[2],
                                iface.MACaddr[3], iface.MACaddr[4], iface.MACaddr[5]};

    //Elegimos el grupo de la sala.
    int estacion = elegirGrupo() + 48;
    type[0] = estacion;
    
    /*
    *Bucle principal
    */
    //Abrimos el puerto
    Puerto = OpenAdapter(&iface);
    if (Puerto != 0)
    {
        printf("Error al abrir el puerto.\n");
        exit(1);
    }
    else
    {
        printf("\nPuerto abierto.\n");
        elegirMaestroEsclavo(iface, mac_src, type);

        Puerto = CloseAdapter(&iface);
        printf("Puerto cerrado\n");
    }

    return 0;
}