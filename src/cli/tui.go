package main

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func MakeTUI() {
	app := tview.NewApplication()

    newBorderedBox := func(text string) tview.Primitive {
        return tview.NewBox().SetBorder(true).SetTitle(text);
    }

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			app.Draw()
		})
	textView.SetBorder(true)

	inputField := tview.NewInputField()
	inputField.
		SetLabel(": ").
		SetFieldBackgroundColor(0).
		SetDoneFunc(func(key tcell.Key) {
			text := inputField.GetText()
			inputField.SetText("")
			fmt.Fprintln(textView, text)
		})
	//inputField.SetBorder(true)

	flex := tview.NewFlex().
		AddItem(tview.NewBox().SetBorder(true).SetTitle("Left (20 cols)"), 20, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(newBorderedBox("Top (3 rows)"), 3, 1, false).
			AddItem(textView, 0, 1, false). // auto expand
			AddItem(inputField, 3, 1, false), 0, 2, false). // Bottom (3 rows)
		AddItem(newBorderedBox("Right (20 cols)"), 20, 1, false)
	
	if err := app.SetRoot(flex, true).SetFocus(inputField).Run(); err != nil {
		panic(err)
	}
}
