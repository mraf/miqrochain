#pragma once
#include <QWidget>
class RpcClient;
class QTimer;
class QTableWidget;
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;
class QProgressBar;

class WalletWidget : public QWidget {
Q_OBJECT
public:
explicit WalletWidget(RpcClient &rpc, QWidget *parent=nullptr);
private:
void refresh();
void refreshUtxo();
void refreshHistory();
void sendTransaction();

RpcClient &m_rpc;
QTimer *m_timer{nullptr};
QLabel *m_balance{nullptr};
QLabel *m_balanceDetails{nullptr};
QLabel *m_pendingLabel{nullptr};
QTableWidget *m_utxo{nullptr};
QTableWidget *m_history{nullptr};
QLineEdit *m_to{nullptr};
QLineEdit *m_amt{nullptr};
QLineEdit *m_fee{nullptr};
QPushButton *m_sendBtn{nullptr};
QProgressBar *m_sendProgress{nullptr};
};
