#pragma once
#include <QObject>
#include <QString>


class AppSettings : public QObject {
Q_OBJECT
public:
explicit AppSettings(QObject *parent=nullptr);
QString rpcUrl() const; // e.g. http://127.0.0.1:9834/
void setRpcUrl(const QString &);


QString daemonPath() const; // path to miqrod
void setDaemonPath(const QString &);


QString confPath() const; // path to miq.conf
void setConfPath(const QString &);


bool autoReadCookie() const; // read token via cookie/env
void setAutoReadCookie(bool);


QString manualToken() const; // only used if autoReadCookie=false
void setManualToken(const QString &);


void load();
void save() const;


signals:
void changed();


private:
QString m_rpcUrl;
QString m_daemonPath;
QString m_confPath;
bool m_autoReadCookie{true};
QString m_manualToken;
};
