import type { App } from 'vue'
import { ElInputNumber, ElPopconfirm, ElRadioButton, ElRadio, ElRadioGroup, ElEmpty, ElIcon, ElCheckbox, ElDatePicker, ElLoading, ElAlert, ElButton, ElCard, ElDialog, ElForm, ElFormItem, ElInput, ElOption, ElPagination, ElSelect, ElSwitch, ElTable, ElTableColumn, ElTag } from 'element-plus'

export function installElements(app: App) {
 for (const component of [ElInputNumber, ElPopconfirm, ElRadioButton, ElRadio, ElRadioGroup, ElEmpty, ElIcon, ElCheckbox, ElDatePicker, ElAlert, ElButton, ElCard, ElDialog, ElForm, ElFormItem, ElInput, ElOption, ElPagination, ElSelect, ElSwitch, ElTable, ElTableColumn, ElTag]) app.component(component.name!, component)
 app.use(ElLoading)
}
