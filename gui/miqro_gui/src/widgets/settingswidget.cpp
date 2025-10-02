#include "settingswidget.h"
#include "../appsettings.h"
#include "../daemoncontroller.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QFileDialog>


SettingsWidget::SettingsWidget(AppSettings &s, DaemonController &d, QWidget *p)
: QWidget(p), m_settings(s), m_daemon(d){
auto *lay = new QVBoxLayout(this);
lay->addWidget(new QLabel("<h2>Settings</h2>"));


auto addRow = [&](const QString &k, QWidget *w){
auto *row = new QHBoxLayout();
row->addWidget(new QLabel(k)); row->addWidget(w,1);
lay->addLayout(row);
};


m_rpcUrl = new QLineEdit(m_settings.rpcUrl()); addRow("RPC URL", m_rpcUrl);


m_daemonPath = new QLineEdit(m_settings.daemonPath());
auto *browseDaemon = new QPushButton("...");
{
auto *row = new QHBoxLayout();
row->addWidget(new QLabel("Daemon (miqrod)"));
row->addWidget(m_daemonPath,1); row->addWidget(browseDaemon);
lay->addLayout(row);
}


m_confPath = new QLineEdit(m_settings.confPath());
auto *browseConf = new QPushButton("...");
{
auto *row = new QHBoxLayout();
row->addWidget(new QLabel("Config (miq.conf)"));
row->addWidget(m_confPath,1); row->addWidget(browseConf);
lay->addLayout(row);
}


m_autoCookie = new QCheckBox("Auto‑read token from cookie/env"); m_autoCookie->setChecked(s.autoReadCookie());
lay->addWidget(m_autoCookie);
m_manualToken = new QLineEdit(s.manualToken()); m_manualToken->setPlaceholderText("Manual token (if auto disabled)");
addRow("Manual token", m_manualToken);


auto *save = new QPushButton("Save");
auto *start= new QPushButton("Start node");
auto *stop = new QPushButton("Stop node");
auto *row = new QHBoxLayout(); row->addWidget(save); row->addWidget(start); row->addWidget(stop); lay->addLayout(row);
lay->addStretch(1);


connect(browseDaemon,&QPushButton::clicked,this,[this]{
const QString f = QFileDialog::getOpenFileName(this, "Select miqrod");
if (!f.isEmpty()) m_daemonPath->setText(f);
});
connect(browseConf,&QPushButton::clicked,this,[this]{
const QString f = QFileDialog::getOpenFileName(this, "Select miq.conf");
if (!f.isEmpty()) m_confPath->setText(f);
});


connect(save,&QPushButton::clicked,this,[this]{
m_settings.setRpcUrl(m_rpcUrl->text());
m_settings.setDaemonPath(m_daemonPath->text());
m_settings.setConfPath(m_confPath->text());
m_settings.setAutoReadCookie(m_autoCookie->isChecked());
m_settings.setManualToken(m_manualToken->text());
m_settings.save();
});


}
