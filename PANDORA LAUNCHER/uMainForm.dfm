object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'Pandora Launcher'
  ClientHeight = 381
  ClientWidth = 560
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnShow = FormShow
  TextHeight = 15
  object lblStatus: TLabel
    Left = 12
    Top = 312
    Width = 536
    Height = 15
    AutoSize = False
    Caption = 'Ready.'
  end
  object memLog: TMemo
    Left = 12
    Top = 12
    Width = 536
    Height = 260
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object barProgress: TProgressBar
    Left = 12
    Top = 280
    Width = 536
    Height = 24
    TabOrder = 1
  end
  object btnRun: TButton
    Left = 12
    Top = 336
    Width = 180
    Height = 32
    Caption = 'Check, update && run'
    TabOrder = 2
    OnClick = btnRunClick
  end
  object btnExit: TButton
    Left = 368
    Top = 336
    Width = 180
    Height = 32
    Caption = 'Exit'
    TabOrder = 3
    OnClick = btnExitClick
  end
  object tmrAuto: TTimer
    Enabled = False
    Interval = 400
    OnTimer = tmrAutoTimer
    Left = 264
    Top = 336
  end
end
