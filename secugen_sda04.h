#ifndef SECUGENSDA04_H
#define SECUGENSDA04_H

#include <QTimer>
#include <ifingerprint.h>
#include <QtSerialPort/QtSerialPort>
#include <wiringPi.h>
#include <QFile>

#define HEADER_PICTURE_FULL_SIZE "424de63401000000000036040000280000000401000"\
    "02c0100000100080000000000b0300100c21e0000c21e00000001000000000000000000"\
    "00010101000202020003030300040404000505050006060600070707000808080009090"\
    "9000a0a0a000b0b0b000c0c0c000d0d0d000e0e0e000f0f0f0010101000111111001212"\
    "1200131313001414140015151500161616001717170018181800191919001a1a1a001b1"\
    "b1b001c1c1c001d1d1d001e1e1e001f1f1f002020200021212100222222002323230024"\
    "24240025252500262626002727270028282800292929002a2a2a002b2b2b002c2c2c002"\
    "d2d2d002e2e2e002f2f2f00303030003131310032323200333333003434340035353500"\
    "363636003737370038383800393939003a3a3a003b3b3b003c3c3c003d3d3d003e3e3e0"\
    "03f3f3f0040404000414141004242420043434300444444004545450046464600474747"\
    "0048484800494949004a4a4a004b4b4b004c4c4c004d4d4d004e4e4e004f4f4f0050505"\
    "00051515100525252005353530054545400555555005656560057575700585858005959"\
    "59005a5a5a005b5b5b005c5c5c005d5d5d005e5e5e005f5f5f006060600061616100626"\
    "26200636363006464640065656500666666006767670068686800696969006a6a6a006b"\
    "6b6b006c6c6c006d6d6d006e6e6e006f6f6f00707070007171710072727200737373007"\
    "474740075757500767676007777770078787800797979007a7a7a007b7b7b007c7c7c00"\
    "7d7d7d007e7e7e007f7f7f0080808000818181008282820083838300848484008585850"\
    "0868686008787870088888800898989008a8a8a008b8b8b008c8c8c008d8d8d008e8e8e"\
    "008f8f8f009090900091919100929292009393930094949400959595009696960097979"\
    "70098989800999999009a9a9a009b9b9b009c9c9c009d9d9d009e9e9e009f9f9f00a0a0"\
    "a000a1a1a100a2a2a200a3a3a300a4a4a400a5a5a500a6a6a600a7a7a700a8a8a800a9a"\
    "9a900aaaaaa00ababab00acacac00adadad00aeaeae00afafaf00b0b0b000b1b1b100b2"\
    "b2b200b3b3b300b4b4b400b5b5b500b6b6b600b7b7b700b8b8b800b9b9b900bababa00b"\
    "bbbbb00bcbcbc00bdbdbd00bebebe00bfbfbf00c0c0c000c1c1c100c2c2c200c3c3c300"\
    "c4c4c400c5c5c500c6c6c600c7c7c700c8c8c800c9c9c900cacaca00cbcbcb00cccccc0"\
    "0cdcdcd00cecece00cfcfcf00d0d0d000d1d1d100d2d2d200d3d3d300d4d4d400d5d5d5"\
    "00d6d6d600d7d7d700d8d8d800d9d9d900dadada00dbdbdb00dcdcdc00dddddd00deded"\
    "e00dfdfdf00e0e0e000e1e1e100e2e2e200e3e3e300e4e4e400e5e5e500e6e6e600e7e7"\
    "e700e8e8e800e9e9e900eaeaea00ebebeb00ececec00ededed00eeeeee00efefef00f0f"\
    "0f000f1f1f100f2f2f200f3f3f300f4f4f400f5f5f500f6f6f600f7f7f700f8f8f800f9"\
    "f9f900fafafa00fbfbfb00fcfcfc00fdfdfd00fefefe00ffffff00"

#define HEADER_PICTURE_HALF_SIZE "424d8e510000000000003604000028000000820000"\
    "00960000000100080000000000000000000000000000000000000000000000000000000"\
    "00001010100020202000303030004040400050505000606060007070700080808000909"\
    "09000a0a0a000b0b0b000c0c0c000d0d0d000e0e0e000f0f0f001010100011111100121"\
    "21200131313001414140015151500161616001717170018181800191919001a1a1a001b"\
    "1b1b001c1c1c001d1d1d001e1e1e001f1f1f00202020002121210022222200232323002"\
    "424240025252500262626002727270028282800292929002a2a2a002b2b2b002c2c2c00"\
    "2d2d2d002e2e2e002f2f2f0030303000313131003232320033333300343434003535350"\
    "0363636003737370038383800393939003a3a3a003b3b3b003c3c3c003d3d3d003e3e3e"\
    "003f3f3f004040400041414100424242004343430044444400454545004646460047474"\
    "70048484800494949004a4a4a004b4b4b004c4c4c004d4d4d004e4e4e004f4f4f005050"\
    "50005151510052525200535353005454540055555500565656005757570058585800595"\
    "959005a5a5a005b5b5b005c5c5c005d5d5d005e5e5e005f5f5f00606060006161610062"\
    "626200636363006464640065656500666666006767670068686800696969006a6a6a006"\
    "b6b6b006c6c6c006d6d6d006e6e6e006f6f6f0070707000717171007272720073737300"\
    "7474740075757500767676007777770078787800797979007a7a7a007b7b7b007c7c7c0"\
    "07d7d7d007e7e7e007f7f7f008080800081818100828282008383830084848400858585"\
    "00868686008787870088888800898989008a8a8a008b8b8b008c8c8c008d8d8d008e8e8"\
    "e008f8f8f00909090009191910092929200939393009494940095959500969696009797"\
    "970098989800999999009a9a9a009b9b9b009c9c9c009d9d9d009e9e9e009f9f9f00a0a"\
    "0a000a1a1a100a2a2a200a3a3a300a4a4a400a5a5a500a6a6a600a7a7a700a8a8a800a9"\
    "a9a900aaaaaa00ababab00acacac00adadad00aeaeae00afafaf00b0b0b000b1b1b100b"\
    "2b2b200b3b3b300b4b4b400b5b5b500b6b6b600b7b7b700b8b8b800b9b9b900bababa00"\
    "bbbbbb00bcbcbc00bdbdbd00bebebe00bfbfbf00c0c0c000c1c1c100c2c2c200c3c3c30"\
    "0c4c4c400c5c5c500c6c6c600c7c7c700c8c8c800c9c9c900cacaca00cbcbcb00cccccc"\
    "00cdcdcd00cecece00cfcfcf00d0d0d000d1d1d100d2d2d200d3d3d300d4d4d400d5d5d"\
    "500d6d6d600d7d7d700d8d8d800d9d9d900dadada00dbdbdb00dcdcdc00dddddd00dede"\
    "de00dfdfdf00e0e0e000e1e1e100e2e2e200e3e3e300e4e4e400e5e5e500e6e6e600e7e"\
    "7e700e8e8e800e9e9e900eaeaea00ebebeb00ececec00ededed00eeeeee00efefef00f0"\
    "f0f000f1f1f100f2f2f200f3f3f300f4f4f400f5f5f500f6f6f600f7f7f700f8f8f800f"\
    "9f9f900fafafa00fbfbfb00fcfcfc00fdfdfd00fefefe00ffffff00"

class DataContainer : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QByteArray ack READ ack WRITE setAck)
    Q_PROPERTY(QByteArray packet READ packet WRITE setPacket)
    Q_PROPERTY(QString command READ command)
    Q_PROPERTY(QString param1 READ param1)
    Q_PROPERTY(QString param1 READ param2)
    Q_PROPERTY(QString checkSum READ checkSum)
    Q_PROPERTY(QString stringError READ stringError)
    Q_PROPERTY(int error READ error)
    Q_PROPERTY(uint packetSize READ packetSize)
    Q_PROPERTY(uint id READ id)

public:

    DataContainer(QObject *parent=0) : QObject(parent)
    {
    }

    void setAck(const QByteArray &a)
    {
        m_ack = a;
    }

    QByteArray ack() const
    {
        return m_ack;
    }

    void setPacket(const QByteArray &a)
    {
        m_packet = a;
    }

    QByteArray packet() const
    {
        return m_packet;
    }

    QString command()
    {
        return "0x" + QString::number(m_ack[1], 16);
    }

    QString param1()
    {
        QString s1 = (QString::number(m_ack[3], 16).length() == 1)? ("0" + QString::number(m_ack[3], 16)) : QString::number(m_ack[3], 16);
        QString s2 = (QString::number(m_ack[2], 16).length() == 1)? ("0" + QString::number(m_ack[2], 16)) : QString::number(m_ack[2], 16);

        return "0x" + s1 + s2;
    }

    uint id()
    {
        bool ok;
        QString s1 = (QString::number(m_ack[3], 16).length() == 1)? ("0" + QString::number(m_ack[3], 16)) : QString::number(m_ack[3], 16);
        QString s2 = (QString::number(m_ack[2], 16).length() == 1)? ("0" + QString::number(m_ack[2], 16)) : QString::number(m_ack[2], 16);

        QString hexId = s1 + s2;
        return hexId.toUInt(&ok,10);
    }

    QString param2()
    {
        QString s1 = (QString::number(m_ack[5], 16).length() == 1)? ("0" + QString::number(m_ack[5], 16)) : QString::number(m_ack[5], 16);
        QString s2 = (QString::number(m_ack[4], 16).length() == 1)? ("0" + QString::number(m_ack[4], 16)) : QString::number(m_ack[4], 16);

        return  "0x" + s1 + s2;
    }

    QString checkSum()
    {
        return  "0x" + QString::number(m_ack[11], 16);
    }

    QString stringError()
    {
        return  "0x" + QString::number(m_ack[10], 16);
    }

    int error()
    {
        return  m_ack[10];
    }

    uint packetSize()
    {
        bool ok;
        QString s1 = (QString::number(m_ack[9], 16).length() == 1)? ("0" + QString::number(m_ack[9], 16)) : QString::number(m_ack[9], 16);
        QString s2 = (QString::number(m_ack[8], 16).length() == 1)? ("0" + QString::number(m_ack[8], 16)) : QString::number(m_ack[8], 16);
        QString s3 = (QString::number(m_ack[7], 16).length() == 1)? ("0" + QString::number(m_ack[7], 16)) : QString::number(m_ack[7], 16);
        QString s4 = (QString::number(m_ack[6], 16).length() == 1)? ("0" + QString::number(m_ack[6], 16)) : QString::number(m_ack[6], 16);

        QString hexSize = "0x" + s1 + s2 + s3 + s4;
        return hexSize.toUInt(&ok,16);
    }

private:
    QByteArray m_ack;
    QByteArray m_packet;
};

class SecugenSda04 : public IFingerprint
{
    Q_OBJECT
    Q_INTERFACES(IFingerprint)
    Q_ENUMS(ErrorReader)

public:
    explicit SecugenSda04(const QString serialPort = "/dev/ttyAMA0");
    void setSerialPort(qint32 baudRate);
    QVariant scanFinger();
    bool verifyFinger(int userID);
    int getImage(QByteArray &img, int imageSize = SecugenSda04::IMAGE_FULL_SIZE);
    int getuserIDavailable();
    QList<int> getuserIDs();

    int registerNewUserStart(int userID);
    int registerNewUserEnd(int userID);
    int getHashUser(int userID, QString &hash64);
    QTimer *timerFinger;

    enum ErrorReader{
        ERROR_NONE = 0x00, // Performs the command received from main controller or host (no error)
        ERROR_FLASH_OPEN = 0x01, // Command from main controller or host to access flash memory failed due to problem(s) in flash memory
        ERROR_SENSOR_OPEN = 0x02, // Failure caused by optic module
        ERROR_REGISTER_FAILED = 0x03, // Fingerprint registration failed
        ERROR_VERIFY_FAILED = 0x04, // Fingerprint verification failed
        ERROR_ALREADY_REGISTERED_USER = 0x05, // UserID already exists
        ERROR_USER_NOT_FOUND = 0x06, // UserID is not found in the SDA04 database
        ERROR_TIMEOUT = 0x08, // Failed to capture fingerprint in preset time
        ERROR_DB_FULL = 0x09, // SDA04 database has insufficient space to enroll a new user
        ERROR_DB_WRONG_USERID = 0x0A, // Failure in removing or verifying an unregistered user
        ERROR_DB_NO_DATA = 0x0B, // Database has no data
        ERROR_EXTRACT_FAIL = 0x0C, // Failed to capture feature points of fingerprint
        ERROR_FUNCTION_FAIL = 0x10, // Function call failed
        ERROR_INSUFFICIENT_DATA = 0x11, // Received data size doesn’t match the size defined in ExtraData
        ERROR_FLASH_WRITE_ERROR = 0x12, // Writing in flash memory failed
        ERROR_INVALID_PARAM = 0x14, // Parameter of packet is invalid
        ERROR_MASTERFP_NOT_FOUND = 0x15, // Fingerprint of master cannot be found (occurs when trying to proceed without master registration)
        ERROR_MASTERCOUNT_EXCEED = 0x16, // Number of masters exceeds five (no more than five masters can be registered)
        ERROR_AUTHENTICATION_FAIL = 0x17, // Verification of master failed
        ERROR_IDENTIFY_FAILED = 0x1B, // No fingerprint in database matches fingerprint in input window
        ERROR_INVALID_USERDATA_SIZE = 0x20, // While recording values from SDA04 to host, size of data exceeded the user portion
        ERROR_INVALID_USERDATA_ADDRESS = 0x21, // User portion of data was exceeded while recording values from SDA04 to host
        ERROR_AUTO_ON_MODE = 0x23, // The size of host user portion is not set
        ERROR_NOT_AUTO_ON_MODE = 0x24, // CMD_FP_AUTO_IDENTIFY is now processing; no other operation can be performed.
        ERROR_CHECKSUM_ERROR = 0x28, // Protocol checksum error
        ERROR_INVALID_FPRECORD = 0x30, // Record format is invalid
        ERROR_UNKNOWN_COMMAND = 0xFF //Commands unknown
    };

    enum formatMinutiae{
        SG400 = 0,
        ANSI378 = 1
    };

    enum ImageSize{
        IMAGE_FULL_SIZE = 0,
        IMAGE_HALF_SIZE = 1
    };

protected:
    bool error;
    void executeCommand(const char cmd, DataContainer &dataContainer, const char param1Hight = 0x00, const char param1Low = 0x00, const char param2Hight = 0x00, const char param2Low = 0x00,const char lwExtraDataHight = 0x00,const char lwExtraDataLow = 0x00,const char hwExtraDataHight = 0x00,const char hwExtraDataLow = 0x00, quint32 baudRate = QSerialPort::Baud9600, QByteArray data= QByteArray());

private:
    QSerialPort serial;
    QByteArray response;
    QString serialPort;
    int timeoutSerial;
    int integerFromArray(QByteArray array, int start, int lenght = 2);
    QString characterToHexQString(const char character);
    std::vector<int> intToHex(int id);

private slots:
    virtual void checkFingerTouch() = 0;

public slots:
    void waitForFinger();
    void stopWaitForFinger();
    int deleteUser(int userID);
    int registerUser(QString hash, int userID, bool replace = false, int format = SecugenSda04::ANSI378);

signals:
    void resultReady(DataContainer *data);
    void partialComplete(int percentage);

};

#endif // CREDENCIAL_H
