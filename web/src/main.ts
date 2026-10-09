import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import { ElAlert, ElButton, ElCard, ElDialog, ElForm, ElFormItem, ElInput, ElOption, ElPagination, ElSelect, ElSwitch, ElTable, ElTableColumn, ElTag } from 'element-plus'
import 'element-plus/es/components/alert/style/css'
import 'element-plus/es/components/button/style/css'
import 'element-plus/es/components/card/style/css'
import 'element-plus/es/components/dialog/style/css'
import 'element-plus/es/components/form/style/css'
import 'element-plus/es/components/form-item/style/css'
import 'element-plus/es/components/input/style/css'
import 'element-plus/es/components/select/style/css'
import 'element-plus/es/components/option/style/css'
import 'element-plus/es/components/pagination/style/css'
import 'element-plus/es/components/switch/style/css'
import 'element-plus/es/components/table/style/css'
import 'element-plus/es/components/table-column/style/css'
import 'element-plus/es/components/tag/style/css'
import App from './App.vue'
import './style.css'
const router = createRouter({ history: createWebHistory(), routes: ['/login', '/', '/websites', '/websites/:id', '/incidents', '/backups'].map(path => ({ path, component: { render: () => null } })) })
const app = createApp(App)
for (const component of [ElAlert, ElButton, ElCard, ElDialog, ElForm, ElFormItem, ElInput, ElOption, ElPagination, ElSelect, ElSwitch, ElTable, ElTableColumn, ElTag]) app.component(component.name!, component)
app.use(router).mount('#app')
