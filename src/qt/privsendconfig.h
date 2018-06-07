#ifndef privsendconfig_H
#define privsendconfig_H

#include <QDialog>

namespace Ui {
    class PrivsendConfig;
}
class WalletModel;

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class PrivsendConfig : public QDialog
{
    Q_OBJECT

public:

    PrivsendConfig(QWidget *parent = 0);
    ~PrivsendConfig();

    void setModel(WalletModel *model);


private:
    Ui::PrivsendConfig *ui;
    WalletModel *model;
    void configure(bool enabled, int coins, int rounds);

private Q_SLOTS:

    void clickBasic();
    void clickHigh();
    void clickMax();
};

#endif // privsendconfig_H
