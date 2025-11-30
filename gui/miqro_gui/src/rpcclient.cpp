#include "rpcclient.h"
#include "appsettings.h"
#include "util/cookie.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QEventLoop>
#include <QTimer>
#include <stdexcept>

static QJsonValue parseOrThrow(const QByteArray &data){
    const auto doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) throw std::runtime_error("Invalid JSON RPC response");
    const auto obj = doc.object();
    if (obj.contains("error") && !obj.value("error").isNull()) {
        const auto err = obj.value("error").toObject();
        const QString msg = err.value("message").toString();
        throw std::runtime_error(msg.isEmpty() ? "RPC error" : msg.toStdString());
    }
    return obj.value("result");
}

RpcClient::RpcClient(AppSettings &s, QObject *p) : QObject(p), m_settings(s) {}

QString RpcClient::authToken(QString *err) const {
    if (m_settings.autoReadCookie()) return util::readCookieToken(err);
    return m_settings.manualToken();
}

QJsonValue RpcClient::call(const QString &method, QJsonArray params){
    QNetworkAccessManager nam;
    QNetworkRequest req(m_settings.rpcUrl());
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QString err; const QString tok = authToken(&err);
    if (tok.isEmpty()) throw std::runtime_error(err.isEmpty() ? "Missing RPC token" : err.toStdString());
    req.setRawHeader("Authorization", QByteArray("Bearer ") + tok.toUtf8());

    QJsonObject body{{"method", method}, {"params", params}};
    const QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);

    QEventLoop loop; QTimer timer; timer.setSingleShot(true);  // ✅ true (not True)
    timer.setInterval(30000);

    QNetworkReply *rep = nam.post(req, payload);
    QObject::connect(rep, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);

    timer.start(); loop.exec();
    if (!timer.isActive()) { rep->abort(); throw std::runtime_error("RPC timeout"); }

    if (rep->error() != QNetworkReply::NoError) {
        const QString m = rep->errorString();
        rep->deleteLater();
        throw std::runtime_error(QString("RPC transport error: %1").arg(m).toStdString());
    }

    const QByteArray data = rep->readAll(); rep->deleteLater();
    return parseOrThrow(data);
}

QJsonValue RpcClient::version()        { return call("version"); }
QJsonValue RpcClient::getTipInfo()     { return call("gettipinfo"); }
QJsonValue RpcClient::getMinerStats()  { return call("getminerstats"); }
QJsonValue RpcClient::getWalletInfo()  { return call("getwalletinfo"); }
QJsonValue RpcClient::listAddresses(int c){ return call("listaddresses", QJsonArray{ c }); }
QJsonValue RpcClient::listUtxos()      { return call("listutxos"); }
QJsonValue RpcClient::walletUnlock(const QString &p, int t){ return call("walletunlock", QJsonArray{ p, t }); }
QJsonValue RpcClient::walletLock()     { return call("walletlock"); }
QJsonValue RpcClient::sendFromHd(const QString &to, const QString &amt, quint64 fee){
    return call("sendfromhd", QJsonArray{ to, amt, QString::number(fee) });
}

// Mempool methods
QJsonValue RpcClient::getMempoolInfo() { return call("getmempoolinfo"); }
QJsonValue RpcClient::getRawMempool()  { return call("getrawmempool"); }

// Wallet history
QJsonValue RpcClient::getWalletHistory(int limit) {
    return call("getwallethistory", QJsonArray{ limit });
}
