#include "logswidget.h"
#include "../daemoncontroller.h"
#include <QVBoxLayout>
#include <QPlainTextEdit>
#include <QPushButton>


LogsWidget::LogsWidget(DaemonController &d, QWidget *p) : QWidget(p){
auto *lay = new QVBoxLayout(this);
m_out = new QPlainTextEdit(); m_out->setReadOnly(true); lay->addWidget(m_out,1);
auto *clear = new QPushButton("Clear"); lay->addWidget(clear);
QObject::connect(clear, &QPushButton::clicked, m_out, &QPlainTextEdit::clear);
QObject::connect(&d, &DaemonController::logLine, this, [this](const QString &ln){ m_out->appendPlainText(ln); });
}
