#include "overviewwidget.h"
#include "../rpcclient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QJsonObject>

class KV : public QWidget {
public:
    KV(const QString &k, const QString &v, QWidget *p=nullptr) : QWidget(p){
        auto *l = new QHBoxLayout(this);
        l->addWidget(new QLabel(QString("<b>%1</b>").arg(k)));
        m_v = new QLabel(v); l->addWidget(m_v, 1);
    }
    void setV(const QString &v){ m_v->setText(v); }
private:
    QLabel *m_v{nullptr};
};

OverviewWidget::OverviewWidget(RpcClient &rpc, QWidget *p) : QWidget(p), m_rpc(rpc){
    auto *lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel("<h2>Overview</h2>"));

    auto *hHeight = new KV("Height", "-");
    auto *hHash   = new KV("Best Hash", "-");
    auto *hBits   = new KV("Bits", "-");

    lay->addWidget(hHeight);
    lay->addWidget(hHash);
    lay->addWidget(hBits);
    lay->addStretch(1);

    m_timer = new QTimer(this);
    m_timer->setInterval(2000);
    connect(m_timer, &QTimer::timeout, this, [this, hHeight, hHash, hBits]{
        try {
            const auto v = m_rpc.getTipInfo().toObject();
            hHeight->setV(QString::number(v.value("height").toInt()));
            hHash->setV(v.value("best_hash").toString());
            hBits->setV(QString::number(v.value("bits").toInt()));
        } catch (...) {}
    });
    m_timer->start();
}
