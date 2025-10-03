#pragma once
#include <QObject>
#include <QJsonValue>
#include <QJsonArray>   // ✅ ensure this is included

class AppSettings;

class RpcClient : public QObject {
    Q_OBJECT
public:
    explicit RpcClient(AppSettings &settings, QObject *parent=nullptr);

    // ✅ take by value with a real default (no reference default to `{}`)
    QJsonValue call(const QString &method, QJsonArray params = QJsonArray());

    // Convenience wrappers
    QJsonValue version();
    QJsonValue getTipInfo();
    QJsonValue getMinerStats();
    QJsonValue getWalletInfo();
    QJsonValue listAddresses(int count=-1);
    QJsonValue listUtxos();
    QJsonValue walletUnlock(const QString &pass, int timeoutSec);
    QJsonValue walletLock();
    QJsonValue sendFromHd(const QString &to, const QString &amount, quint64 feeRate=0);

private:
    AppSettings &m_settings;
    QString authToken(QString *err) const;
};
