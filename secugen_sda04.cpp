#include "secugen_sda04.h"
#define CMD_GET_VERSION 0x05

SecugenSda04::SecugenSda04(const QString serialPort): IFingerprint() {

    error = false;
    timeoutSerial = 5;
    serial.setPortName(serialPort);
    qDebug() << "Init fingerprintreader Secugen SDA04 : " << serialPort;

    if(error)
        qCritical() << "Fingerprintreader not detected";
}

void SecugenSda04::setSerialPort(qint32 baudRate)
{
    if(!serial.isOpen())
    {
        if (!serial.open(QIODevice::ReadWrite)) {
            qCritical() << "error open : " << serial.errorString() << "(code : " << serial.error() << ")";
        }
    }

    if (!serial.setBaudRate(baudRate)) {
        qCritical() << "Can't set baud rate " << baudRate << " baud to port " << serialPort << ", error code " << serial.error();
    }

    if (!serial.setDataBits(QSerialPort::Data8)) {
        qCritical() << "Can't set 8 data bits to port " << serialPort << ", error code " << serial.error();
    }

    if (!serial.setParity(QSerialPort::NoParity)) {
        qCritical() << "Can't set no parity to port " << serialPort << ", error code " << serial.error();
    }

    if (!serial.setStopBits(QSerialPort::OneStop)) {
        qCritical() << "Can't set 1 stop bit to port " << serialPort << ", error code " << serial.error();
    }

    if (!serial.setFlowControl(QSerialPort::NoFlowControl)) {
        qCritical() << "Can't set no flow control to port " << serialPort << ", error code " << serial.error();
    }

    serial.clearError();
}

void SecugenSda04::waitForFinger()
{
    timerFinger = new QTimer();
    connect(timerFinger, &QTimer::timeout, this, &SecugenSda04::checkFingerTouch);
    qDebug() << "Init read FINGERPRINT process";
    timerFinger->start(500);
}

void SecugenSda04::stopWaitForFinger()
{
    if(timerFinger && !error)
        timerFinger->stop();
}

int SecugenSda04::getuserIDavailable()
{
    QList<int> ids;
    int i = 1;
    ids = getuserIDs();

    while(i <= 9999)
    {
        if(ids.contains(i))
            i++;
        else
            break;
    }

    qDebug() << "New ID for fingerprint : "  << i;

    return i;
}

QList<int> SecugenSda04::getuserIDs()
{
    DataContainer dataContainer;
    QByteArray data;
    QString u;
    QSet<int> ids;
    int id;
    bool ok;
    QList<int> list;

    executeCommand(0x7d,dataContainer,0x00,0x01);

    QString numberIDs = dataContainer.param1();
    uint sizeID = numberIDs.toUInt(&ok,16);

    if(dataContainer.error() == SecugenSda04::ERROR_DB_NO_DATA)
        qDebug() << "ID Empty";
    else {

        qDebug() << "Number of ID : " << QString::number(sizeID);

        data = dataContainer.packet();
        int i = 0;

        for(uint j = 0; j < sizeID; j++)
        {
            QString hVal = (QString::number(data[i+1], 16).length() == 1)? ("0" + QString::number(data[i+1], 16)) : QString::number(data[i+1], 16);
            QString lVal = (QString::number(data[i+0], 16).length() == 1)? ("0" + QString::number(data[i+0], 16)) : QString::number(data[i+0], 16);

            u = hVal + lVal;
            id = u.toInt(&ok,10);

            ids.insert(id);
            i = i + 12;
        }

        list = QList<int>::fromSet(ids);
        qSort(list);
    }

    return list;
}

int SecugenSda04::integerFromArray(QByteArray array, int start, int lenght)
{
    int num = 0;
    QByteArray cut = array.mid(start,lenght);
    bool ok;

    if(lenght==1)
    {
        num = QString::number(cut[0], 16).toUInt(&ok,16);

    } else {

        QString hg = QString::number(cut[0], 16).right(2);
        QString lo = QString::number(cut[1], 16).right(2);

        lo = lo.length() == 1? "0" + lo:lo;
        num = (hg + lo).toUInt(&ok,16);
    }

    return (!ok)? 0 : num;
}

int SecugenSda04::registerUser(QString hash, int userID, bool replace, int format)
{
    QByteArray binHash;
    binHash.append(hash);
    binHash = QByteArray::fromBase64(binHash);

    int sizeM = (format == SecugenSda04::ANSI378)? 800 : 400;

    int sizeFingerprint = 2 + 2 + (sizeM * 2) + 11 + 1;
    QByteArray newFingerprint;
    newFingerprint.resize(sizeFingerprint);

    std::vector<int> hexs = intToHex(userID);
    // User ID :
    newFingerprint[0] = hexs[0];
    newFingerprint[1] = hexs[1];
    // Master :
    newFingerprint[2] = 0x00;
    newFingerprint[3] = 0x00;

    // Check number of template :
    int sizeTotal = binHash.size();

    qDebug() << "Hash detail :";
    qDebug() << "Format : " << (format == SecugenSda04::ANSI378? "ANSI:378" : "SG400");
    qDebug() << "Size total hash : " << sizeTotal;
    qDebug() << "Size minutiae data to create : " << sizeFingerprint;

    if(format == SecugenSda04::ANSI378)
    {
        int sizeT1 = integerFromArray(binHash,8);

        QByteArray t1;
        QByteArray t2;
        int sizeT2;

        if(sizeTotal == sizeT1)
        {
            qDebug() << "Number of template : 1";

            t1 = binHash.left(sizeT1);
            t2 = binHash.left(sizeT1);
            sizeT2 = sizeT1;

            qDebug() << "Size template T1 : " << sizeT1;

        } else { // 2 template

            qDebug() << "Number of template : 2";

            t1 = binHash.left(sizeT1);
            t2 = binHash.right(sizeTotal-sizeT1);
            sizeT2 = integerFromArray(t2,8);

            qDebug() << "Size template T1 : " << sizeT1;
            qDebug() << "Size template T2 : " << sizeT2;
        }

        newFingerprint.replace(4,sizeT1,t1);

        for(int i = sizeT1 + 4;i<= 1600 + 4;i++)
            newFingerprint[i] = 0x00;

        newFingerprint.replace(800 + 4,sizeT2,t2);

        for(int i = 1600 + 4;i< sizeFingerprint;i++)
            newFingerprint[i] = 0xFF;

    }

    if(format == SecugenSda04::SG400)
    {
        newFingerprint.replace(4,sizeTotal,binHash);

        for(int i = 800 + 4;i< sizeFingerprint;i++)
            newFingerprint[i] = 0xFF;
    }

    // Parameters :
    const char sizeParam2L = (format == SecugenSda04::ANSI378)? 0x06 : 0x03;
    const char sizeParam2H = (format == SecugenSda04::ANSI378)? 0x50 : 0x30;
    const char change = replace? 0x01 : 0x00;

    DataContainer dataContainer;
    executeCommand(0x71,dataContainer,0x00,change,0x00,0x00,sizeParam2L,sizeParam2H,0x00,0x00,QSerialPort::Baud9600,newFingerprint);

    if(dataContainer.error() == SecugenSda04::ERROR_INSUFFICIENT_DATA)
        return -1;
    if(dataContainer.error() == SecugenSda04::ERROR_INVALID_FPRECORD)
        return -2;

    return 0;
}

int SecugenSda04::registerNewUserStart(int userID)
{
    DataContainer dataContainer;
    std::vector<int> hexs = intToHex(userID);
    executeCommand(0x50,dataContainer,hexs[1],hexs[0]);

    if(dataContainer.error() == SecugenSda04::ERROR_TIMEOUT)
        return 1;
    if(dataContainer.error() == SecugenSda04::ERROR_DB_FULL)
        return 2;
    if(dataContainer.error() == SecugenSda04::ERROR_ALREADY_REGISTERED_USER)
        return 3;

    return 0;
}

int SecugenSda04::registerNewUserEnd(int userID)
{
    DataContainer dataContainer;
    std::vector<int> hexs = intToHex(userID);
    executeCommand(0x51,dataContainer,hexs[1],hexs[0]);

    if(dataContainer.error() == SecugenSda04::ERROR_TIMEOUT)
        return 1;
    if(dataContainer.error() == SecugenSda04::ERROR_REGISTER_FAILED)
        return 2;
    if(dataContainer.error() == SecugenSda04::ERROR_FLASH_WRITE_ERROR)
        return 3;
    if(dataContainer.error() == SecugenSda04::ERROR_USER_NOT_FOUND)
        return 4;

    return 0;
}

int SecugenSda04::deleteUser(int userID) {

    DataContainer dataContainer;
    std::vector<int> hexs = intToHex(userID);
    executeCommand(0x54,dataContainer,hexs[1],hexs[0]);

    if(dataContainer.error() == SecugenSda04::ERROR_USER_NOT_FOUND)
        return 1;
    if(dataContainer.error() == SecugenSda04::ERROR_FLASH_WRITE_ERROR)
        return 2;

    return 0;
}

int SecugenSda04::getHashUser(int userID, QString &hash64)
{
    DataContainer dataContainer;
    std::vector<int> hexs = intToHex(userID);
    executeCommand(0x73,dataContainer,hexs[1],hexs[0]);
    QString tempHash;

    if(dataContainer.packetSize() > 0)
    {
        tempHash = dataContainer.packet().toBase64();
        std::string hash = tempHash.toStdString();
        hash64 = QString::fromStdString(hash);

        return 0;

    } else {

        return -1;
    }
}

QVariant SecugenSda04::scanFinger()
{
    qDebug() << "scanFinger";

    DataContainer dataContainer;
    executeCommand(0x56,dataContainer,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

    if(dataContainer.error() == SecugenSda04::ERROR_USER_NOT_FOUND) // ??
        return QVariant(-1);
    if(dataContainer.error() == SecugenSda04::ERROR_IDENTIFY_FAILED)
        return QVariant(-2);
    if(dataContainer.error() == SecugenSda04::ERROR_TIMEOUT)
        return QVariant(-3);

    return QVariant(dataContainer.id());
}

bool SecugenSda04::verifyFinger(int userID)
{
    DataContainer dataContainer;
    std::vector<int> hexs = intToHex(userID);
    executeCommand(0x55,dataContainer,hexs[1],hexs[0]);

    return (dataContainer.error() == 0);
}

int SecugenSda04::getImage(QByteArray &img, int imageSize)
{
    QByteArray data;
    QByteArray header;
    DataContainer dataContainer;
    QString headerHex;

    headerHex = (imageSize == SecugenSda04::IMAGE_FULL_SIZE)? HEADER_PICTURE_FULL_SIZE : HEADER_PICTURE_HALF_SIZE;
    const char sizeCmd = (imageSize == SecugenSda04::IMAGE_FULL_SIZE)? 0x01 : 0x02;

    executeCommand(0x43,dataContainer,0x00,sizeCmd,0x00,0x00);

    header = QByteArray::fromHex(headerHex.toLatin1());
    data = dataContainer.packet();

    if(imageSize == SecugenSda04::IMAGE_HALF_SIZE)
    {
        char *imageByte = data.data();
        char *tempData = new char[19800];

        for(int i=0 ; i<150 ; i++)
            memcpy(tempData+(150-i-1)*132, imageByte+i*130, 130);

        data = QByteArray::fromRawData(tempData,19800);
    }

    img = header + data;

    qDebug() << "Header image size : " << header.size();
    qDebug() << "Raw image size    : " << data.size();
    qDebug() << "Image size        : " << img.size();

    //QFile file("/home/pi/client-timer/test00.bmp");
    //file.open(QIODevice::WriteOnly);
    //file.write(img);
    //file.close();

    // TODO: error reader

    return 0;
}

void SecugenSda04::executeCommand(const char cmd, DataContainer &dataContainer, const char param1Hight, const char param1Low, const char param2Hight, const char param2Low ,const char lwExtraDataHight,const char lwExtraDataLow,const char hwExtraDataHight,const char hwExtraDataLow, quint32 baudRate, QByteArray data)
{
    setSerialPort(baudRate);

    const char channel = 0x00;
    const char stub = 0x00;

    int cks = ((int)cmd + (int)param1Hight + (int)param1Low + (int)param2Hight + (int)param2Low +(int)lwExtraDataLow + (int)lwExtraDataHight + (int)hwExtraDataLow + (int)hwExtraDataHight) % 256;
    const char checkSum[] = { cks };

    serial.write(&channel,1); // channel 1 byte (alway the same)
    serial.write(&cmd,1); // command 1 byte
    serial.write(&param1Low,1); // param1 2 bytes (byte low)
    serial.write(&param1Hight,1); // param1 2 bytes (byte hight)
    serial.write(&param2Low,1); // param2 2 bytes (byte low)
    serial.write(&param2Hight,1); // param2 2 bytes (byte hight)
    serial.write(&lwExtraDataLow,1); // lwExtraData 2 bytes (byte low)
    serial.write(&lwExtraDataHight,1); // lwExtraData 2 bytes (byte hight)
    serial.write(&hwExtraDataLow,1); // hwExtraData 2 bytes (byte low)
    serial.write(&hwExtraDataHight,1); // hwExtraData 2 bytes (byte hight)
    serial.write(&stub,1); // ErrorCode 1 byte
    serial.write(&checkSum[0],1); // Checksum 1 byte

    if(!data.isEmpty())
        serial.write(data.constData(),data.size());

    //qDebug() << "Serial input :";
    //qDebug() << "Serial baud  :" << serial.baudRate();
    //qDebug() << "command      :" << "0x" + characterToHexQString(cmd);
    //qDebug() << "param1       :" << "0x" + characterToHexQString(param1Hight) + characterToHexQString(param1Low) + "(Hight:" + characterToHexQString(param1Hight) + "/Low:" + characterToHexQString(param1Low) + ")";
    //qDebug() << "param2       :" << "0x" + characterToHexQString(param2Hight) + characterToHexQString(param2Low) + "(Hight:" + characterToHexQString(param2Hight) + "/Low:" + characterToHexQString(param2Low) + ")";
    //qDebug() << "Check sum    :" << "0x" + characterToHexQString(checkSum[0]);

    QString completeCommand = characterToHexQString(channel);
    completeCommand += " " + characterToHexQString(cmd);
    completeCommand += " " + characterToHexQString(param1Low);
    completeCommand += " " + characterToHexQString(param1Hight);
    completeCommand += " " + characterToHexQString(param2Low);
    completeCommand += " " + characterToHexQString(param2Hight);
    completeCommand += " " + characterToHexQString(lwExtraDataLow);
    completeCommand += " " + characterToHexQString(lwExtraDataHight);
    completeCommand += " " + characterToHexQString(hwExtraDataLow);
    completeCommand += " " + characterToHexQString(hwExtraDataHight);
    completeCommand += " " + characterToHexQString(stub);
    completeCommand += " " + characterToHexQString(checkSum[0]);
    //qDebug() << "complete     :" <<  completeCommand;

    if (serial.waitForBytesWritten(1000)) {

        QByteArray ack;
        int i = 0;

        while(ack.size() < 12 && i < timeoutSerial)
        {
            if(serial.waitForReadyRead(10000))
                ack += serial.readAll();
            i++;
        }

        if(i == timeoutSerial) {

            error = true;

            qCritical() << "serial timeout error";

        } else {

            dataContainer.setAck(ack);
            int completeSize = dataContainer.packetSize();

#ifdef QT_DEBUG
            qDebug() << "Serial response :";
            qDebug() << "ACK Error : " << dataContainer.stringError();
            qDebug() << "Check sum : " << dataContainer.checkSum();
            qDebug() << "Parameter 01 : " << dataContainer.param1();
            qDebug() << "Parameter 02 : " << dataContainer.param2();
            qDebug() << "ACK Packet size : " << completeSize;
#endif
            if(dataContainer.error() == SecugenSda04::ERROR_NONE)
            {
                if(completeSize > 0)
                {
#ifdef QT_DEBUG
                    qDebug() << "get the data packet on the serial port ...";
#endif
                    QByteArray data = ack.right(ack.size() - 12);

                    while(data.size() < completeSize)
                        if(serial.waitForReadyRead(100))
                            data += serial.readAll();
#ifdef QT_DEBUG
                    qDebug() << "data received (size : " << data.size() << ")";
#endif
                    if (data.size() > 0)
                        dataContainer.setPacket(data);
                }

            } else {
                emit sendError(dataContainer.error());
            }
        }

    }

    serial.close();
}

QString SecugenSda04::characterToHexQString(const char character)
{
    QString result = QString::number(character, 16);
    result = (result == "0") ? "00" : result;
    return (result.length() == 1)? "0" + result : result;
}

std::vector<int> SecugenSda04::intToHex(int id)
{
    QString ident = QString::number(id);
    std::vector<int> hexValues(2);

    hexValues[0] = 0x00;
    hexValues[1] = 0x00;
    bool ok;

    if(ident.length() < 3)
    {
        hexValues[0] = ident.toUInt(&ok,16);

    } else {

        hexValues[0] = ident.right(2).toUInt(&ok,16);
        hexValues[1] = ident.left(ident.length()-2).toUInt(&ok,16);
    }

    return hexValues;
}
