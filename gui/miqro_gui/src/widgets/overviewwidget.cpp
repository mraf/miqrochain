#include "overviewwidget.h"
#include "../rpcclient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QJsonObject>
#include <QGroupBox>
#include <QFrame>
#include <QDateTime>

class KV : public QWidget {
public:
    KV(const QString &k, const QString &v, QWidget *p=nullptr) : QWidget(p){
        auto *l = new QHBoxLayout(this);
        l->setContentsMargins(5, 2, 5, 2);
        auto *kl = new QLabel(QString("<b>%1:</b>").arg(k));
        kl->setMinimumWidth(120);
        l->addWidget(kl);
        m_v = new QLabel(v);
        m_v->setTextInteractionFlags(Qt::TextSelectableByMouse);
        l->addWidget(m_v, 1);
    }
    void setV(const QString &v){ m_v->setText(v); }
    void setError(){ m_v->setText("<span style='color: #cc0000;'>Connection error</span>"); }
private:
    QLabel *m_v{nullptr};
};

OverviewWidget::OverviewWidget(RpcClient &rpc, QWidget *p) : QWidget(p), m_rpc(rpc){
    auto *lay = new QVBoxLayout(this);

    // Title with version
    auto *titleLay = new QHBoxLayout();
    titleLay->addWidget(new QLabel("<h2>Miqrochain Core v1.0.0</h2>"));
    titleLay->addStretch(1);
    m_status = new QLabel("<span style='color: green;'>Connecting...</span>");
    titleLay->addWidget(m_status);
    lay->addLayout(titleLay);

    // Chain info group
    auto *chainGroup = new QGroupBox("Blockchain Status");
    auto *chainLay = new QVBoxLayout(chainGroup);

    auto *hHeight = new KV("Block Height", "-");
    auto *hHash   = new KV("Best Hash", "-");
    auto *hBits   = new KV("Difficulty", "-");
    auto *hTime   = new KV("Block Time", "-");

    chainLay->addWidget(hHeight);
    chainLay->addWidget(hHash);
    chainLay->addWidget(hBits);
    chainLay->addWidget(hTime);

    lay->addWidget(chainGroup);
    lay->addStretch(1);

    // Footer
    auto *footer = new QLabel("<small>Miqrochain - Production Ready Blockchain</small>");
    footer->setAlignment(Qt::AlignCenter);
    lay->addWidget(footer);

    m_timer = new QTimer(this);
    m_timer->setInterval(2000);
    connect(m_timer, &QTimer::timeout, this, [this, hHeight, hHash, hBits, hTime]{
        try {
            const auto v = m_rpc.getTipInfo().toObject();
            hHeight->setV(QString::number(v.value("height").toInt()));
            QString hash = v.value("hash").toString();
            if (hash.length() > 24) {
                hash = hash.left(12) + "..." + hash.right(12);
            }
            hHash->setV(hash);
            hBits->setV(v.value("bits").toString());
            qint64 time = static_cast<qint64>(v.value("time").toDouble());
            QDateTime dt = QDateTime::fromSecsSinceEpoch(time);
            hTime->setV(dt.toString("yyyy-MM-dd hh:mm:ss"));
            m_status->setText("<span style='color: green;'>Connected</span>");
        } catch (const std::exception &e) {
            hHeight->setError();
            hHash->setError();
            hBits->setError();
            hTime->setError();
            m_status->setText(QString("<span style='color: red;'>Disconnected: %1</span>").arg(QString::fromStdString(e.what()).left(30)));
        } catch (...) {
            m_status->setText("<span style='color: red;'>Disconnected</span>");
        }
    });
    m_timer->start();
}
