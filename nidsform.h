#ifndef NIDSFORM_H
#define NIDSFORM_H

#include <QWidget>
#include <QComboBox>

namespace Ui {
class NidsForm;
}

class NidsForm : public QWidget
{
    Q_OBJECT
    
public:
    explicit NidsForm(QWidget *parent = 0);
    ~NidsForm();
    
private slots:
    void on_comboBoxProto_currentIndexChanged(int index);

    void on_comboBoxAlarm_currentIndexChanged(int index);

private:
    void setCombox (QComboBox* pCombox,QStringList itemList);
private:
    Ui::NidsForm *ui;
};

#endif // NIDSFORM_H
