// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "guiutil.h"
#include "transactiondescdialog.h"
#include "ui_transactiondescdialog.h"

#include "transactiontablemodel.h"

#include <QModelIndex>
#include <QSettings>
#include <QString>
#include <QPushButton>

TransactionDescDialog::TransactionDescDialog(const QModelIndex &idx, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TransactionDescDialog)
{
    ui->setupUi(this);
    this->setWindowFlags(Qt::Dialog|Qt::WindowCloseButtonHint);
    ui->buttonBox->button(QDialogButtonBox::Close)->setText(tr("Close"));

    /* Open CSS when configured */
    this->setStyleSheet(GUIUtil::loadStyleSheet());

    QString desc = idx.data(TransactionTableModel::LongDescriptionRole).toString();
    ui->detailText->setHtml(desc);
}

TransactionDescDialog::~TransactionDescDialog()
{
    delete ui;
}
