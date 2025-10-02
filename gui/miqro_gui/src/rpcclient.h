#pragma once
#include <QObject>
#include <QJsonValue>
#include <QNetworkReply>


class AppSettings;


class RpcClient : public QObject {
Q_OBJECT
public:
explicit RpcClient(AppSettings &settings, QObject *parent=nullptr);


// Convenience wrappers return QJsonValue (object/array/primitive); throw on error
QJsonValue call(const QString &method, const QJsonArray &params = {});


// Syntactic sugar
QJsonValue version();
QJsonValue getTipInfo();
QJsonValue getMinerStats();
QJsonValue getWalletInfo();
QJsonValue listAddresses(int count=-1);
QJsonValue listUtxos();
QJsonValue walletUnlock(const QString &pass, int timeoutSec);
QJsonValue walletLock();
QJsonValue sendFromHd(const QString &to, const QString &amount, quint64 feeRate = 0);


private:
AppSettings &m_settings;
QString authToken(QString *err) const; // cookie or manual
};
