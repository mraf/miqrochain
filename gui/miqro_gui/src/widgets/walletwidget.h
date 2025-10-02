#pragma once
#include <QWidget>
class RpcClient; class QTimer; class QTableWidget; class QLabel; class QLineEdit; class QPushButton;


class WalletWidget : public QWidget {
Q_OBJECT
public:
explicit WalletWidget(RpcClient &rpc, QWidget *parent=nullptr);
private:
void refresh();
void refreshUtxo();


RpcClient &m_rpc;
QTimer *m_timer{nullptr};
QLabel *m_balance{nullptr};
QTableWidget *m_utxo{nullptr};
QLineEdit *m_to{nullptr};
QLineEdit *m_amt{nullptr};
QLineEdit *m_fee{nullptr};
};
