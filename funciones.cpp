#include "funciones.h"

//============================================================================
// ----------- PRACTICAS DE FUNDAMENTOS DE REDES DE COMUNICACIONES -----------
// ---------------------------- CURSO 2020/21 --------------------------------
// ----------------------------- FUNCIONES.CPP ---------------------------------
// ---------------- ABEL GONZALO BARBA Y ANGEL CAÑADA MUÑOZ ------------------
//============================================================================

/************* MENUS *************/
void cabecera()
{
    printf("\n--------------------------------------\n");
    printf("---- ENTREGA FINAL PRACTICA - FRC ----\n");
    printf("--------------------------------------\n\n");
}

void mostrarInterfaces(pcap_if_t *avail_ifaces)
{
    avail_ifaces = GetAvailAdapters();
    int i = 0;
    printf("Interfaces disponibles:\n");
    while (avail_ifaces != NULL)
    {
        printf("[%i] %s\n", i, avail_ifaces->name);

        avail_ifaces = avail_ifaces->next;
        i++;
    }
}

void seleccionarInterfaz(pcap_if_t *avail_ifaces, interface_t &iface)
{
    avail_ifaces = GetAvailAdapters();
    char o;

    printf("\nSelecione interfaz: ");
    int opcion;
    cin >> opcion;

    if (opcion >= 0 && opcion < sizeof(avail_ifaces))
    {
        int j = 0;
        while (j < opcion)
        {
            avail_ifaces = avail_ifaces->next;
            j++;
        }

        setDeviceName(&iface, avail_ifaces->name);
        GetMACAdapter(&iface);

        printf("Interfaz Elegida: %s\n", iface.deviceName);
        printf("La MAC es: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
               (unsigned char)iface.MACaddr[0],
               (unsigned char)iface.MACaddr[1],
               (unsigned char)iface.MACaddr[2],
               (unsigned char)iface.MACaddr[3],
               (unsigned char)iface.MACaddr[4],
               (unsigned char)iface.MACaddr[5]);
    }
    else
    {
        printf("Opcion incorrecta.\n");
    }
}

int elegirGrupo()
{
    int grupo;

    printf("Introduzca el numero de grupo: ");
    cin >> grupo;

    return grupo;
}

void elegirMaestroEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *type)
{
    int modo;

    printf("\nSeleccione el modo de la estacion: \n");
    printf("[1] Modo Maestra.\n");
    printf("[2] Modo Esclava.\n");
    printf("Modo: ");
    cin >> modo;

    bool recibidaTramaMaestro = false;
    bool recibidaTramaEsclava = false;
    unsigned char broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    unsigned char *tramaDescubrimentoEsclavo;

    apacket_t tramaMaestro;
    apacket_t tramaEsclavo;

    unsigned char mac_dst[6];

    switch (modo)
    {
    case 1: //Maestro

        type[1] = 0x01;
        descubrimientoMaestro(iface, mac_src, broadcast, type);

        cout << "Esperando a que se una la estacion esclava.\n"
             << endl;

        while (!recibidaTramaEsclava)
        {
            tramaEsclavo = ReceiveFrame(&iface);
            if (tramaEsclavo.packet != NULL)
            { //Compruebo que es la trama recibida es la de descubrimiento.
                if (tramaEsclavo.packet[12] == type[0] && tramaEsclavo.packet[13] == 0x02)
                {
                    cout << "GRUPO: " << tramaEsclavo.packet[12] << endl;
                    cout << "Estación esclava encontrada." << endl;
                    printf("La MAC es: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                           tramaEsclavo.packet[6],
                           tramaEsclavo.packet[7],
                           tramaEsclavo.packet[8],
                           tramaEsclavo.packet[9],
                           tramaEsclavo.packet[10],
                           tramaEsclavo.packet[11]);
                    recibidaTramaEsclava = true;
                }
            }
        }

        memcpy(mac_dst, tramaEsclavo.packet + 6, 6);
        type[1] = 0x00;

        elegirModoEnvioMaestro(iface, mac_src, mac_dst, type);

        break;

    case 2: //Esclavo

        cout << "Esperando a que se una la estacion maestra.\n"
             << endl;
        while (!recibidaTramaMaestro)
        { //Espero trama maestro
            tramaMaestro = ReceiveFrame(&iface);
            if (tramaMaestro.packet != NULL)
            { //Compruebo que es la trama recibida es la de descubrimiento.
                if (tramaMaestro.packet[12] == type[0] && tramaMaestro.packet[13] == 0x01)
                {
                    cout << "GRUPO: " << tramaMaestro.packet[12] << endl;
                    cout << "Estación maestra encontrada." << endl;
                    printf("La MAC es: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                           tramaMaestro.packet[6],
                           tramaMaestro.packet[7],
                           tramaMaestro.packet[8],
                           tramaMaestro.packet[9],
                           tramaMaestro.packet[10],
                           tramaMaestro.packet[11]);
                    type[1] = 0x02;
                    memcpy(mac_dst, tramaMaestro.packet + 6, 6);

                    //EConstruyo trama
                    tramaDescubrimentoEsclavo = BuildHeader(mac_src, mac_dst, type);
                    //Envio trama.
                    SendFrame(&iface, tramaDescubrimentoEsclavo, 0);

                    recibidaTramaMaestro = true;
                }
            }
        }

        type[1] = 0x00;

        elegirModoEnvioEsclavo(iface, mac_src, mac_dst, type);

        break;

    default:
        cout << "Error al elegir el modo." << endl;
    }
}

void elegirModoEnvioMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char modoEnvio;

    printf("\nSeleccione el modo de envio:\n");
    printf("[F1] Envio de caracteres interactivo.\n");
    printf("[F2] Envio de un fichero.\n");
    printf("[F3] Protocolo paro y espera.\n");
    printf("[ESC] Salir.\n\n");

    __fpurge(stdin);
    while (modoEnvio != F1 && modoEnvio != F2 && modoEnvio != F3 && modoEnvio != F4)
    {
        if (kbhit())
        {
            modoEnvio = (unsigned char)getch();
            if (modoEnvio == ESC)
            {
                if (kbhit())
                {
                    modoEnvio = (unsigned char)getch();
                    if (modoEnvio == caracter2)
                    {
                        modoEnvio = (unsigned char)getch();

                        switch (modoEnvio)
                        {
                        case F1:
                            cout << endl
                                 << "Seleccionado: Envio de caracteres interactivo." << endl;

                            buclePrincipal(iface, mac_src, mac_dst, type);
                            elegirModoEnvioMaestro(iface, iface.MACaddr, mac_dst, type);
                            break;

                        case F2:
                            cout << "\nEnviando fichero..." << endl;
                            enviarFichero(iface, mac_dst, type);
                            elegirModoEnvioMaestro(iface, iface.MACaddr, mac_dst, type);
                            break;

                        case F3:
                            protocoloMaestro(iface, mac_src, mac_dst, type);
                            break;

                        default:
                            elegirModoEnvioMaestro(iface, iface.MACaddr, mac_dst, type);
                            break;
                        }
                    }
                }
                else
                {
                    printf("\nSaliendo de la aplicacion...\n");
                    exit(1);
                }
            }
            else
            {
                printf("\nPulsa una de las opciones de la lista.\n");
                elegirModoEnvioMaestro(iface, mac_src, mac_dst, type);
            }
        }
    }
}

void elegirModoEnvioEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char modoEnvio;

    printf("\nSeleccione el modo de envio:\n");
    printf("[F1] Envio de caracteres interactivo.\n");
    printf("[F2] Protocolo paro y espera.\n");
    printf("[ESC] Salir.\n\n");

    __fpurge(stdin);
    while (modoEnvio != F1 && modoEnvio != F2 && modoEnvio != F3 && modoEnvio != F4)
    {
        recibir(iface, type);

        if (kbhit())
        {
            modoEnvio = (unsigned char)getch();
            if (modoEnvio == ESC)
            {
                if (kbhit())
                {
                    modoEnvio = (unsigned char)getch();
                    if (modoEnvio == caracter2)
                    {
                        modoEnvio = (unsigned char)getch();

                        switch (modoEnvio)
                        {
                        case F1:
                            cout << endl
                                 << "Seleccionado: Envio de caracteres interactivo" << endl;
                            buclePrincipal(iface, mac_src, mac_dst, type);
                            elegirModoEnvioEsclavo(iface, iface.MACaddr, mac_dst, type);
                            break;

                        case F2:
                            protocoloEsclavo(iface, mac_src, mac_dst, type);
                            break;

                        default:
                            elegirModoEnvioEsclavo(iface, iface.MACaddr, mac_dst, type);
                            break;
                        }
                    }
                }
                else
                {
                    printf("\nSaliendo de la aplicacion...\n");
                    exit(1);
                }
            }
            else
            {
                printf("\nPulsa una de las opciones de la lista.\n");
                elegirModoEnvioEsclavo(iface, mac_src, mac_dst, type);
            }
        }
    }
}

/*********** FUNCIONES ***********/
void EnviarCaracter(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, unsigned char tecla)
{
    unsigned char *datos = (unsigned char *)malloc(1 * sizeof(unsigned char));
    unsigned char *trama = (unsigned char *)malloc(85 * sizeof(unsigned char));

    datos[0] = tecla;

    trama = BuildFrame(mac_src, mac_dst, type, datos);
    SendFrame(&iface, trama, 1);

    free(datos);
    free(trama);
}

void descubrimientoMaestro(interface_t iface, unsigned char *mac_src, unsigned char *broadcast, unsigned char *type)
{
    unsigned char *tramaDescubrimento;

    tramaDescubrimento = BuildHeader(mac_src, broadcast, type);
    SendFrame(&iface, tramaDescubrimento, 0);
}

void descubrimientoEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char *tramaDescubrimento;

    tramaDescubrimento = BuildHeader(mac_src, mac_dst, type);
    SendFrame(&iface, tramaDescubrimento, 0);
}

void enviarFichero(interface_t iface, unsigned char *mac_dst, unsigned char *type)
{
    ifstream fLectura;
    unsigned char cadena[254];
    int tamanoTotal = 0;
    fLectura.open("Fenvio.txt");

    if (fLectura.is_open())
    {
        while (!fLectura.eof())
        {
            fLectura.read((char *)cadena, 254);
            cadena[fLectura.gcount()] = '\0';

            if (fLectura.gcount() > 0)
            {
                enviarTramaFichero(iface, mac_dst, type, cadena, fLectura.gcount());
            }
        }
    }
    else
    {
        printf("ERROR: El fichero Fenvio.txt no existe\n");
    }

    fLectura.close();
}

void enviarTramaFichero(interface_t iface, unsigned char *mac_dst, unsigned char *type, unsigned char *cadena, int tamanoTrama)
{
    unsigned char *trama = BuildFrame(iface.MACaddr, mac_dst, type, cadena);
    SendFrame(&iface, trama, tamanoTrama);
}

void protocoloMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    __fpurge(stdin);

    printf("\nProtocolo paro y espera. Estas en modo Maestro.\n");
    printf("Seleccione el tipo de operacion:\n");
    printf("[1] Operacion Seleccion.\n");
    printf("[2] Operacion Sondeo.\n");
    printf("[3] Salir.\n");

    unsigned char op;

    int operacion;
    cin >> operacion;

    cout << endl;

    switch (operacion)
    {
    case 1:
        op = 'R';

        establecimientoSeleccion(iface, mac_src, mac_dst, type);
        esperaProtocoloMaestro(iface, mac_src, mac_dst, type);
        cout << endl;

        transferencia(iface, mac_src, mac_dst, type, op);
        cout << endl;

        solicitarCierreProtocolo(iface, mac_src, mac_dst, type, op, '0');
        //esperaProtocoloMaestro(iface, mac_src, mac_dst, type);

        elegirModoEnvioMaestro(iface, mac_src, mac_dst, type);

        break;

    case 2:
        establecimientoSondeo(iface, mac_src, mac_dst, type);

        esperaProtocoloMaestro(iface, mac_src, mac_dst, type);
        cout << endl;
        cout << endl;

        recibirFicheroMaestro(iface, mac_src, mac_dst, type);

        cout << endl;

        break;

    case 3:
        elegirModoEnvioMaestro(iface, mac_src, mac_dst, type);
        break;

    default:
        printf("Seleccione una opcion de la lista.\n");

        protocoloMaestro(iface, mac_src, mac_dst, type);
        break;
    }
}

void protocoloEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    cout << endl
         << "Protocolo paro y espera. Pulsa ESC para salir." << endl
         << "Estas en modo Esclavo." << endl
         << endl;
    esperaProtocoloEsclavo(iface, mac_src, mac_dst, type);
}

void establecimientoSeleccion(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char *trama = BuildFrame(mac_src, mac_dst, type, crearTramaControl('R', ENQ, '0'));

    if (trama[15] == ENQ)
        cout << "E " << trama[14] << " "
             << "ENQ"
             << " " << trama[16] << endl;

    SendFrame(&iface, trama, 3);
}

void transferencia(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, unsigned char operacion)
{
    ifstream fLectura;
    unsigned char cadena[254];
    fLectura.open("EProtoc.txt");
    int i = 0;

    if (fLectura.is_open())
    {
        while (!fLectura.eof())
        {
            fLectura.read((char *)cadena, 254);
            cadena[fLectura.gcount()] = '\0';

            unsigned char *trama = (unsigned char *)malloc((fLectura.gcount() + 5) * sizeof(unsigned char));

            if (i % 2 == 0)
            {
                trama = crearTramaDatos(operacion, STX, '0', cadena, (int)fLectura.gcount());
            }
            else
            {
                trama = crearTramaDatos(operacion, STX, '1', cadena, (int)fLectura.gcount());
            }

            if (fLectura.gcount() > 0)
            {
                cout << "E " << trama[0] << " "
                     << "STX"
                     << " " << trama[2] << " "; //printf trama[trama[3] + 4]
                printf("%d \n", trama[trama[3] + 4]);
                enviarTramaFichero(iface, mac_dst, type, trama, (int)fLectura.gcount() + 5);
                free(trama);

                esperaProtocoloMaestro(iface, mac_src, mac_dst, type);
            }

            i++;
        }

    }
    else
    {
        printf("ERROR: El fichero Fenvio.txt no existe\n");
    }

    fLectura.close();
}

void solicitarCierreProtocolo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, unsigned char op, char nTrama)
{
    unsigned char *trama;
    apacket_t tramaCierre;
    unsigned char *payload;
    unsigned char control;
    bool fin = false;

    if (op == 'T')
    {
        trama = BuildFrame(mac_src, mac_dst, type, crearTramaControl('T', EOT, nTrama));
    }

    if (op == 'R')
    {
        trama = BuildFrame(mac_src, mac_dst, type, crearTramaControl('R', EOT, nTrama));
    }

    if (trama[15] == EOT)
        cout << endl
             << "E " << trama[14] << " "
             << "EOT"
             << " " << trama[16] << endl;

    SendFrame(&iface, trama, 3);

    do
    {
        tramaCierre = ReceiveFrame(&iface);
        payload = (unsigned char *)tramaCierre.packet;

        if (payload)
        {
            if (payload[12] == type[0] && payload[13] == 0x00)
            {
                // cout << "GRUPO: " << payload[12] << endl;
                control = payload[15];

                if (control == ACK && payload[14] == 'T')
                {
                    cout << "R " << payload[14] << " "
                         << "ACK"
                         << " " << payload[16] << endl
                         << endl;

                    cout << "Fin de sondeo por parte del Esclavo." << endl;

                    fin = true;
                }

                if (control == ACK && payload[14] == 'R')
                {
                    cout << "R " << payload[14] << " "
                         << "ACK"
                         << " " << payload[16] << endl
                         << endl;

                    cout << "Fin de seleccion por parte del Maestro." << endl;

                    fin = true;
                }

                if (control == NACK && payload[14] == 'T')
                {
                    cout << "R " << payload[14] << " "
                         << "NACK"
                         << " " << payload[16] << endl;

                    if (nTrama == '0')
                    {
                        solicitarCierreProtocolo(iface, mac_src, mac_dst, type, op, '1');
                    }

                    if (nTrama == '1')
                    {
                        solicitarCierreProtocolo(iface, mac_src, mac_dst, type, op, '0');
                    }

                    fin = true;
                }
            }
        }
    } while (fin == false);
}

void esperaProtocoloMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char tecla = ' ';
    apacket_t trama;
    unsigned char *payload;
    unsigned char control;
    unsigned char operacion;

    do
    {
        trama = ReceiveFrame(&iface);
        payload = (unsigned char *)trama.packet;

        if (payload)
        {
            if (payload[12] == type[0] && payload[13] == 0x00)
            {
                //   cout << "GRUPO: " << payload[12] << endl;
                control = payload[15];
                operacion = payload[14];

                if (control == ACK && operacion == 'R')
                {
                    cout << "R " << payload[14] << " "
                         << "ACK"
                         << " " << payload[16];
                }

                if (control == ACK && operacion == 'T')
                {
                    cout << "R " << payload[14] << " "
                         << "ACK"
                         << " " << payload[16];
                }
            }
        }

        if (kbhit())
        {
            tecla = (unsigned char)getch();

            if (tecla == ESC)
            {
                elegirModoEnvioMaestro(iface, mac_src, mac_dst, type);
            }
        }
    } while (control != ACK);
}

void esperaProtocoloEsclavo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char tecla = ' ';
    bool fin = false;
    apacket_t trama;
    unsigned char *payload;

    ofstream fEscritura;
    fEscritura.open("RProtoc.txt", ios::out | ios::trunc);

    do
    {
        trama = ReceiveFrame(&iface);
        payload = (unsigned char *)trama.packet;

        if (payload)
        {
            if (payload[12] == type[0] && payload[13] == 0x00)
            {
                //   cout << "GRUPO: " << payload[12] << endl;
                unsigned char cadena[(int)payload[17]]; //Cadena para calculcar BCE
                if (payload[14] == 'R')
                {
                    if (payload[15] == ENQ)
                    {
                        cout << "R " << payload[14] << " "
                             << "ENQ"
                             << " " << payload[16] << endl;
                    }

                    if (payload[15] == STX)
                    {
                        int i = 0;
                        for (i = 0; i < payload[17]; i++)
                        {
                            cadena[i] = payload[i + 18]; //Asigno desde posición 0 de cadena.
                        }
                        cadena[i] = '\0';
                        fEscritura.write((char *)cadena, strlen((char *)cadena));

                        cout << "R " << payload[14] << " "
                             << "STX"
                             << " " << payload[16] << " " << (int)payload[payload[17] + 18] << " " << (int)calcularBCE(cadena) << endl;
                    }

                    if (payload[15] == EOT)
                    {
                        cout << endl;
                        cout << "R " << payload[14] << " "
                             << "EOT"
                             << " " << payload[16] << endl;
                    }

                    unsigned char *tramaEnvio = BuildFrame(mac_src, mac_dst, type, crearTramaControl('R', ACK, payload[16]));
                    SendFrame(&iface, tramaEnvio, sizeof(trama));

                    cout << "E " << payload[14] << " "
                         << "ACK"
                         << " " << payload[16] << endl;

                    if (payload[15] == ENQ)
                    {
                        cout << endl;
                    }
                    
                  
                    if (payload[15] == EOT)
                    {
                        cout << endl
                             << "Fin de seleccion por parte del Esclavo." << endl;

                        fin = true;
                    }
                }

                //MODO SONDEO***********************************************************************
                if (payload[14] == 'T')
                {
                    if (payload[15] == ENQ)
                    {
                        cout << "R " << payload[14] << " "
                             << "ENQ"
                             << " " << payload[16] << endl;
                    }

                    unsigned char *tramaEnvioSondeo = BuildFrame(mac_src, mac_dst, type, crearTramaControl('T', ACK, payload[16]));
                    SendFrame(&iface, tramaEnvioSondeo, sizeof(trama));

                    cout << "E " << tramaEnvioSondeo[14] << " "
                         << "ACK"
                         << " " << tramaEnvioSondeo[16] << endl;

                    transferencia(iface, mac_src, mac_dst, type, 'T');
                    cout << endl;

                    solicitarCierreProtocolo(iface, mac_src, mac_dst, type, 'T', '0');

                    fin = true;
                }
            }
        }

        if (kbhit())
        {
            tecla = (unsigned char)getch();

            if (kbhit())
            {
                tecla = (unsigned char)getch();

                if (kbhit())
                {
                    tecla = (unsigned char)getch();
                    printf("\nTeclas de funcion desactivadas.\n\n");
                }
            }
        }
    } while (fin == false && tecla != ESC);

    fEscritura.close();

    elegirModoEnvioEsclavo(iface, mac_src, mac_dst, type);
}

void establecimientoSondeo(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char *trama = BuildFrame(mac_src, mac_dst, type, crearTramaControl('T', ENQ, '0'));

    if (trama[15] == ENQ)
        cout << "E " << trama[14] << " "
             << "ENQ"
             << " " << trama[16] << endl;

    SendFrame(&iface, trama, 3);
    free(trama);
}

void recibirFicheroMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char tecla = ' ';
    bool fin = false;
    apacket_t trama;
    unsigned char *payload;

    ofstream fEscritura;
    fEscritura.open("RProtoc.txt", ios::out | ios::trunc);

    do
    {
        trama = ReceiveFrame(&iface);
        payload = (unsigned char *)trama.packet;

        if (payload)
        {
            if (payload[12] == type[0] && payload[13] == 0x00)
            {
                //    cout << "GRUPO: " << payload[12] << endl;
                if (payload[15] == STX)
                {
                    unsigned char cadena[(int)payload[17]]; //Cadena para calculcar BCE
                    int i = 0;
                    for (i = 0; i < payload[17]; i++)
                    {
                        cadena[i] = payload[i + 18]; //Asigno desde posición 0 de cadena.
                    }
                    cadena[i] = '\0';

                    fEscritura.write((char *)cadena, strlen((char *)cadena));

                    cout << "R " << payload[14] << " "
                         << "STX"
                         << " " << payload[16] << " " << (int)payload[payload[17] + 18] << " " << (int)calcularBCE(cadena) << endl;
                }

                if (payload[15] == EOT)
                {
                    cout << endl;
                    cout << "R " << payload[14] << " "
                         << "EOT"
                         << " " << payload[16] << endl
                         << endl;

                    cout << "Acepta el cierre de la comunicacion:" << endl
                         << "[1] Si." << endl
                         << "[2] No." << endl;

                    int opcion;
                    cin >> opcion;

                    unsigned char *tramaCierre1;
                    unsigned char *tramaCierre2;
                    switch (opcion)
                    {
                    case 1:
                        tramaCierre1 = BuildFrame(mac_src, mac_dst, type, crearTramaControl('T', ACK, payload[16]));
                        SendFrame(&iface, tramaCierre1, 3);

                        cout << "E " << tramaCierre1[14] << " "
                             << "ACK"
                             << " " << tramaCierre1[16] << endl;

                        fin = true;
                        break;

                    case 2:
                        esperaEOTMaestro(iface, mac_src, mac_dst, type, payload[16]);
                        break;

                    default:
                        printf("Seleccione una opcion de la lista.\n");
                        break;
                    }
                }

                if (fin == false && payload[15] != EOT)
                {
                    unsigned char *tramaEnvio = BuildFrame(mac_src, mac_dst, type, crearTramaControl('T', ACK, payload[16]));
                    SendFrame(&iface, tramaEnvio, 3);

                    cout << "E " << payload[14] << " "
                         << "ACK"
                         << " " << payload[16] << endl;
                }

                if (payload[15] == ENQ)
                {
                    cout << endl;
                }
            }

            if (kbhit())
            {
                tecla = (unsigned char)getch();

                if (tecla == ESC)
                {
                    elegirModoEnvioMaestro(iface, mac_src, mac_dst, type);
                }
            }
        }
    } while (fin == false);

    cout << endl
         << "Fin de sondeo por parte del Maestro." << endl;

    cout << endl;

    fEscritura.close();
    elegirModoEnvioMaestro(iface, mac_src, mac_dst, type);
}

void esperaEOTMaestro(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, char nTrama)
{
    unsigned char *tramaCierre;
    tramaCierre = BuildFrame(mac_src, mac_dst, type, crearTramaControl('T', NACK, nTrama));
    SendFrame(&iface, tramaCierre, 3);

    cout << endl
         << "E " << tramaCierre[14] << " "
         << "NACK"
         << " " << tramaCierre[16] << endl;
}

/*********** PRINCIPAL ***********/
void enviar(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type, unsigned char &tecla)
{
    if (kbhit())
    {
        tecla = (unsigned char)getch();

        if (tecla != ESC)
        {
            EnviarCaracter(iface, mac_src, mac_dst, type, tecla);
        }
        else
        {
            if (kbhit())
            {
                tecla = (unsigned char)getch();

                if (kbhit())
                {
                    tecla = (unsigned char)getch();
                    printf("\nTeclas de funcion desactivadas.\n\n");
                }
            }
        }
    }
}

void recibir(interface_t iface, unsigned char *type)
{
    apacket_t trama = ReceiveFrame(&iface);
    unsigned char *campoDatos = (unsigned char *)trama.packet;

    if (campoDatos)
    {
        if (campoDatos[12] == type[0] && campoDatos[13] == 0x00)
        {
            //  cout << "GRUPO: " << campoDatos[12] << endl;

            int tam = trama.header.len - 14;

            if (tam > 1 && campoDatos[15] != '\0')
            {
                cout << endl;
                printf("Recibido: ");
                for (int i = 0; i <= tam; i++)
                {
                    printf("%c", campoDatos[i + 14]);
                }
                printf("\n");
                cout << "TAMAÑO: " << tam << endl
                     << endl;
            }
            else
            {
                unsigned char teclaR = campoDatos[14];
                printf("Recibido: %c\n", teclaR);
                cout << "TAMAÑO: " << tam << endl
                     << endl;
            }
        }
    }
}

void buclePrincipal(interface_t iface, unsigned char *mac_src, unsigned char *mac_dst, unsigned char *type)
{
    unsigned char tecla;
    unsigned char teclaR;

    while (tecla != ESC)
    {
        //Recibir()
        recibir(iface, type);

        //Enviar
        enviar(iface, mac_src, mac_dst, type, tecla);
    }

    //printf("\nSaliendo de la aplicacion.\n");
}