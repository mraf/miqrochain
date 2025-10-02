#include "consolewidget.h"
#include "../rpcclient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QJsonDocument>
#include <QJsonArray>
#include <QMessageBox>


ConsoleWidget::ConsoleWidget(RpcClient &rpc, QWidget *p) : QWidget(p), m_rpc(rpc){
auto *lay = new QVBoxLayout(this);
m_out = new QPlainTextEdit(); m_out->setReadOnly(true);
lay->addWidget(m_out, 1);


auto *row = new QHBoxLayout();
m_method = new QLineEdit(); m_method->setPlaceholderText("method e.g. gettipinfo");
m_params = new QLineEdit(); m_params->setPlaceholderText("params JSON array e.g. [\"arg\",123]");
auto *go = new QPushButton("Call");
row->addWidget(m_method); row->addWidget(m_params); row->addWidget(go);
lay->addLayout(row);


connect(go, &QPushButton::clicked, this, [this]{
try {
const QString m = m_method->text().trimmed();
const QJsonArray p = QJsonDocument::fromJson(m_params->text().toUtf8()).array();
const auto r = m_rpc.call(m, p);
m_out->appendPlainText(QString::fromUtf8(QJsonDocument(QJsonValue(r).toObject()).toJson()));
} catch (const std::exception &e) {
m_out->appendPlainText(QString("Error: %1").arg(e.what()));
}
});
}
