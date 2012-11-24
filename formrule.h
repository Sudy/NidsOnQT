#ifndef FORMRULE_H
#define FORMRULE_H

#include <QWidget>

namespace Ui {
class FormRule;
}

class FormRule : public QWidget
{
    Q_OBJECT
    
public:
    explicit FormRule(QWidget *parent = 0);
    ~FormRule();
    
private slots:
    void on_btnAddRule_clicked();

    void on_btnOK_clicked();

    void on_btnCancel_clicked();

    void on_comboBoxProto_currentIndexChanged(int index);

    void on_comboBoxAlarm_2_currentIndexChanged(int index);

    void on_comboBoxProto_2_currentIndexChanged(int index);

    void on_btnDelRule_clicked();




private:
    Ui::FormRule *ui;
};

#endif // FORMRULE_H
