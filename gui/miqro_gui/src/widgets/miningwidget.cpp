#include "miningwidget.h"
#include "../rpcclient.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QJsonObject>


MiningWidget::MiningWidget(RpcClient &rpc, QWidget *p) : QWidget(p), m_rpc(rpc){
auto *lay = new QVBoxLayout(this);
lay->addWidget(new QLabel("<h2>Mining</h2>"));
m_height = new QLabel("Height: -"); lay->addWidget(m_height);
m_hash = new QLabel("Hashrate: 0 H/s"); lay->addWidget(m_hash);
lay->addStretch(1);


m_timer = new QTimer(this); m_timer->setInterval(1000);
connect(m_timer, &QTimer::timeout, this, [this]{
try {
const auto v = m_rpc.getMinerStats().toObject();
const auto h = v.value("height").toInt();
const auto hr= v.value("hashrate").toDouble();
m_height->setText(QString("Height: %1").arg(h));
m_hash->setText(QString("Hashrate: %1 H/s").arg(hr,0,'f',0));
} catch (...) {}
});
m_timer->start();
}
