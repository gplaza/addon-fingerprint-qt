#ifndef IFINGERPRINT_H
#define IFINGERPRINT_H
#include <QDebug>

class IFingerprint : public QObject
{
    Q_OBJECT

public :
    virtual ~IFingerprint() {}
    virtual QVariant scanFinger() = 0;
    virtual void waitForFinger() = 0;

public slots:
    virtual void checkFingerTouch() = 0;

signals:
    void fingerDetected();
    void sendError(int error);

};

Q_DECLARE_INTERFACE (IFingerprint,"cl.gplaza.IFingerprint/1.0")

#endif // IFINGERPRINT_H


