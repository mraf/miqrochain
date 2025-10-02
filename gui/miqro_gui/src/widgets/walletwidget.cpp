#include "walletwidget.h"
#include "../rpcclient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QTableWidget>
#include <QHeaderView>
#include <QJsonObject>
#include <QJsonArray>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>


WalletWidget::WalletWidget(RpcClient &rpc, QWidget *p) : QWidget(p), m_rpc(rpc){
auto *lay = new QVBoxLayout(this);
lay->addWidget(new QLabel("<h2>Wallet</h2>"));


m_balance = new QLabel("Balance: 0"); lay->addWidget(m_balance);


// Send form
auto *form = new QHBoxLayout();
m_to = new QLineEdit(); m_to->setPlaceholderText("To Address");
m_amt = new QLineEdit(); m_amt->setPlaceholderText("Amount (miqron)");
m_fee = new QLineEdit(); m_fee->setPlaceholderText("Fee rate (sat/vB, optional)");
auto *send = new QPushButton("Send");
form->addWidget(m_to); form->addWidget(m_amt); form->addWidget(m_fee); form->addWidget(send);
lay->addLayout(form);


m_utxo = new QTableWidget(0, 4);
m_utxo->setHorizontalHeaderLabels({"txid", "vout", "amount", "confirmations"});
m_utxo->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
lay->addWidget(m_utxo, 1);


connect(send, &QPushButton::clicked, this, [this]{
try {
const QString to = m_to->text().trimmed();
const QString amt = m_amt->text().trimmed();
const quint64 fee = m_fee->text().trimmed().isEmpty() ? 0 : m_fee->text().toULongLong();
const auto r = m_rpc.sendFromHd(to, amt, fee);
QMessageBox::information(this, "Send", QString("TXID: %1").arg(r.toString()));
} catch (const std::exception &e) {
QMessageBox::warning(this, "Send failed", e.what());
}
});


m_timer = new QTimer(this); m_timer->setInterval(3000);
connect(m_timer, &QTimer::timeout, this, [this]{ refresh(); });
m_timer->start();
refresh();
}


void WalletWidget::refresh(){
try {
const auto w = m_rpc.getWalletInfo().toObject();
const auto bal = w.value("balance").toString();
const bool locked = w.value("locked").toBool();
const int unlockLeft = w.value("unlock_seconds_left").toInt();
QString line = QString("Balance: %1").arg(bal);
line += locked ? " [Locked]" : " [Unlocked]";
if (!locked && unlockLeft>0) line += QString(" (locks in %1s)").arg(unlockLeft);
m_balance->setText(line);
} catch (...) {}
refreshUtxo();
}


void WalletWidget::refreshUtxo(){
try {
const auto a = m_rpc.listUtxos().toArray();
m_utxo->setRowCount(a.size());
for (int i=0;i<a.size();++i){
const auto o = a[i].toObject();
m_utxo->setItem(i,0,new QTableWidgetItem(o.value("txid").toString()));
m_utxo->setItem(i,1,new QTableWidgetItem(QString::number(o.value("vout").toInt())));
m_utxo->setItem(i,2,new QTableWidgetItem(o.value("amount").toString()));
m_utxo->setItem(i,3,new QTableWidgetItem(QString::number(o.value("confirmations").toInt())));
}
} catch (...) {}
}
