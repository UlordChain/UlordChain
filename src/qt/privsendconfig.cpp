#include "privsendconfig.h"
#include "ui_privsendconfig.h"

#include "bitcoinunits.h"
#include "privsend.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include <QMessageBox>
#include <QPushButton>
#include <QKeyEvent>
#include <QSettings>

PrivsendConfig::PrivsendConfig(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PrivsendConfig),
    model(0)
{
    ui->setupUi(this);

    connect(ui->buttonBasic, SIGNAL(clicked()), this, SLOT(clickBasic()));
    connect(ui->buttonHigh, SIGNAL(clicked()), this, SLOT(clickHigh()));
    connect(ui->buttonMax, SIGNAL(clicked()), this, SLOT(clickMax()));
}

PrivsendConfig::~PrivsendConfig()
{
    delete ui;
}

void PrivsendConfig::setModel(WalletModel *model)
{
    this->model = model;
}

void PrivsendConfig::clickBasic()
{
    configure(true, 1000, 2);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("PrivateSend Configuration"),
        tr(
            "PrivateSend was successfully set to basic (%1 and 2 rounds). You can change this at any time by opening Ulord's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void PrivsendConfig::clickHigh()
{
    configure(true, 1000, 8);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("PrivateSend Configuration"),
        tr(
            "PrivateSend was successfully set to high (%1 and 8 rounds). You can change this at any time by opening Ulord's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void PrivsendConfig::clickMax()
{
    configure(true, 1000, 16);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("PrivateSend Configuration"),
        tr(
            "PrivateSend was successfully set to maximum (%1 and 16 rounds). You can change this at any time by opening Ulord's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void PrivsendConfig::configure(bool enabled, int coins, int rounds) {

    QSettings settings;

    settings.setValue("nPrivateSendRounds", rounds);
    settings.setValue("nPrivateSendAmount", coins);

    nPrivateSendRounds = rounds;
    nPrivateSendAmount = coins;
}
