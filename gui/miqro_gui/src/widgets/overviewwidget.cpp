#include "overviewwidget.h"
#include "../rpcclient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QJsonObject>
#include <QJsonArray>
#include <QGroupBox>
#include <QFrame>
#include <QDateTime>
#include <QTableWidget>
#include <QHeaderView>

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

    // Mempool info group
    auto *mempoolGroup = new QGroupBox("Mempool");
    auto *mempoolLay = new QVBoxLayout(mempoolGroup);

    m_mempoolStats = new QLabel("Transactions: 0 | Size: 0 bytes | Fees: 0 MIQ");
    mempoolLay->addWidget(m_mempoolStats);

    m_mempoolTable = new QTableWidget(0, 3);
    m_mempoolTable->setHorizontalHeaderLabels({"TXID", "Size", "Fee Rate"});
    m_mempoolTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mempoolTable->setMaximumHeight(150);
    m_mempoolTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_mempoolTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mempoolLay->addWidget(m_mempoolTable);

    lay->addWidget(mempoolGroup);

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

            // Refresh mempool info
            refreshMempool();
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

void OverviewWidget::refreshMempool() {
    try {
        // Get mempool info
        const auto info = m_rpc.getMempoolInfo().toObject();
        int txCount = info.value("size").toInt();
        int bytes = info.value("bytes").toInt();
        double totalFees = info.value("total_fees").toDouble();
        double avgFeeRate = info.value("avg_fee_rate").toDouble();

        // Format fees in MIQ (100,000,000 miqron = 1 MIQ)
        QString feesStr = QString::number(totalFees / 100000000.0, 'f', 8);

        m_mempoolStats->setText(QString("Transactions: %1 | Size: %2 bytes | Fees: %3 MIQ | Avg rate: %4 sat/vB")
            .arg(txCount).arg(bytes).arg(feesStr).arg(avgFeeRate, 0, 'f', 2));

        // Get raw mempool for transaction list
        const auto txids = m_rpc.getRawMempool().toArray();
        m_mempoolTable->setRowCount(qMin(txids.size(), 10));  // Show max 10 transactions

        for (int i = 0; i < qMin(txids.size(), 10); ++i) {
            QString txid = txids[i].toString();
            if (txid.length() > 20) {
                txid = txid.left(10) + "..." + txid.right(10);
            }
            m_mempoolTable->setItem(i, 0, new QTableWidgetItem(txid));
            m_mempoolTable->setItem(i, 1, new QTableWidgetItem("-"));  // Size would need getrawtx
            m_mempoolTable->setItem(i, 2, new QTableWidgetItem("-"));  // Fee rate would need getrawtx
        }
    } catch (...) {
        m_mempoolStats->setText("Mempool: Unable to fetch");
        m_mempoolTable->setRowCount(0);
    }
}
