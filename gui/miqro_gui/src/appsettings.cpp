#include "appsettings.h"
#include <QSettings>


AppSettings::AppSettings(QObject *p) : QObject(p) { load(); }


QString AppSettings::rpcUrl() const { return m_rpcUrl.isEmpty() ? QStringLiteral("http://127.0.0.1:9834/") : m_rpcUrl; }
void AppSettings::setRpcUrl(const QString &v){ if (m_rpcUrl==v) return; m_rpcUrl=v; emit changed(); }


QString AppSettings::daemonPath() const { return m_daemonPath; }
void AppSettings::setDaemonPath(const QString &v){ if (m_daemonPath==v) return; m_daemonPath=v; emit changed(); }


QString AppSettings::confPath() const { return m_confPath; }
void AppSettings::setConfPath(const QString &v){ if (m_confPath==v) return; m_confPath=v; emit changed(); }


bool AppSettings::autoReadCookie() const { return m_autoReadCookie; }
void AppSettings::setAutoReadCookie(bool v){ if (m_autoReadCookie==v) return; m_autoReadCookie=v; emit changed(); }


QString AppSettings::manualToken() const { return m_manualToken; }
void AppSettings::setManualToken(const QString &v){ if (m_manualToken==v) return; m_manualToken=v; emit changed(); }


void AppSettings::load(){
QSettings s("Miqrochain", "MiqroGUI");
m_rpcUrl = s.value("rpcUrl", "http://127.0.0.1:9834/").toString();
m_daemonPath = s.value("daemonPath").toString();
m_confPath = s.value("confPath").toString();
m_autoReadCookie = s.value("autoReadCookie", true).toBool();
m_manualToken = s.value("manualToken").toString();
}


void AppSettings::save() const{
QSettings s("Miqrochain", "MiqroGUI");
s.setValue("rpcUrl", m_rpcUrl);
s.setValue("daemonPath", m_daemonPath);
s.setValue("confPath", m_confPath);
s.setValue("autoReadCookie", m_autoReadCookie);
s.setValue("manualToken", m_manualToken);
}
