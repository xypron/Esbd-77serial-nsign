#!/usr/bin/python3
# -*- coding: UTF-8 -*-
#
# SPDX-License-Identifier: Apache-2.0
#
# This file is the UI interface of sign
#
# Copyright 2024 Beijing ESWIN Computing Technology Co., Ltd.
#   Authors:
#    liangshuang <liangshuang@eswincomputing.com>

import tkinter as tk
from tkinter import *
import tkinter.messagebox
import os
import tkinter.ttk as ttk
from tkinter import filedialog
from tkinter import simpledialog
from tkinter.font import Font
import platform
import subprocess
import copy

nsign_version = ''
encrypt_enable = 1

menu_open_file = ''
param_list = []
param_name = ['out', 'in', 'boot_flags', 'payload_type']
param_adv_list = []
param_adv_name = ['sign_algorithm', 'keyid', 'version', 'load_addr', 'entry_addr', 'digest_mthd',
                   'encrypted_mthd', 'devid', 'vid', 'lang', 'mid', 'link_addr', 'params', 'dl_load_addr',
                   'dl_init_ofs', 'dl_destory_ofs', 'dl_ioctl_ofs', 'dl_load_flags', 'dl_irq_num', 'dl_irq_ofs']
payload_count = 0

plat = platform.system().lower()
if plat == 'windows':
    current_path=os.path.abspath(os.path.join(os.getcwd()))
elif plat == 'linux':
    current_path=os.path.abspath(os.path.join(os.getcwd()))
    #If it is opened in the development tool, please use the following line of code to obtain the current program execution path
    #current_path=os.path.abspath(os.curdir)
    #tk.messagebox.showinfo(title='note', message=current_path)

def select_file(file_path):
    selected_file_path = filedialog.askopenfilename()
    file_path.set(selected_file_path)

def select_save_file(file_path):
    selected_file_path = filedialog.asksaveasfilename()
    file_path.set(selected_file_path)


def limitSizeDay(*args,varr,lenn):
	value = varr.get()
	if len(value) > lenn: varr.set(value[:lenn])
#	if not re.match("^[0-9,a-f,A-F]*$", value):  varr.set(value[:len(value)-1])

def show_nsign_message(msg):
    msg_window=tk.Toplevel(root_window)
    msg_window.title('nsign error messages')
    msg_window.geometry('700x600')
    msg_window.attributes('-topmost', True)
    text=Text(msg_window, bg='lightgrey')
    text.config(state=NORMAL)
    text.insert(END, msg)
    text.config(state=DISABLED)
    text.grid(row=0, column=0, sticky='nsew')
    msg_window.grid_rowconfigure(0, weight=1)
    msg_window.grid_columnconfigure(0, weight=1)

def call_sign_exe():
    path=current_path
    if plat == 'windows':
        cmd_run=path+'\\nsign.exe'
    elif plat == 'linux':
        cmd_run=path+'/nsign'
    if not os.path.exists(cmd_run):
        tk.messagebox.showinfo(title='error', message=f'nsign file:{cmd_run} is not exists!')
        return -1
    if not os.access(cmd_run, os.X_OK):
        tk.messagebox.showinfo(title='error', message=f'nsign file:{cmd_run} is not executable!')
        return -1
    res=subprocess.run(args=cmd_run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print("------------nsign error log-------------------")
        print(res.stdout)
        show_nsign_message(res.stdout)
    return res.returncode

def get_sign_exe_version():
    global nsign_version
    global encrypt_enable
    path=current_path
    if plat == 'windows':
        cmd_run=path+'\\nsign.exe'
    elif plat == 'linux':
        cmd_run=path+'/nsign'
    if not os.path.exists(cmd_run):
        tk.messagebox.showinfo(title='error', message=f'nsign file:{cmd_run} is not exists!')
        return -1
    if not os.access(cmd_run, os.X_OK):
        tk.messagebox.showinfo(title='error', message=f'nsign file:{cmd_run} is not executable!')
        return -1
    cmd_run = cmd_run + ' --help'
    res=subprocess.run(args=cmd_run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode == 0:
        words = res.stdout.split()
        sub_words = words[2].split('-')
        nsign_version = 'V' + sub_words[0]
        if 'unencrypted' in sub_words[1]:
            encrypt_enable = 0
        print('version:' + nsign_version + '-' + sub_words[1])

def genkey():
    cmd_genkey='cmd=genkey'
    if plat == 'windows':
        config_file_path=current_path+'\\config.txt'
        key_path = current_path+'\\keys\\'
    elif plat == 'linux':
        config_file_path=current_path+'/config.txt'
        key_path = current_path+'/keys/'

    if not os.path.exists(key_path):
        tk.messagebox.showinfo(title='error', message=f'directory:{key_path} is not exists!')
        return -1
    if not os.access(key_path, os.W_OK):
        tk.messagebox.showinfo(title='error', message=f'directory:{key_path} is not writable!')
        return -1

    with open(config_file_path,"w",encoding="utf-8") as f:
            f.write(cmd_genkey)
    ret = call_sign_exe()
    if ret == 0:
        tk.messagebox.showinfo(title='note', message='success!')
    else:
        tk.messagebox.showinfo(title='error', message='generate key failed!')

class VertNotebook(ttk.Frame):
    label_cnt = 0
    def __init__(self, *args, **kw):
        ttk.Frame.__init__(self, *args, **kw)

        self.rowconfigure(20)
        self.columnconfigure(20)
        for i in range(19):
            self.grid_rowconfigure(i, weight=1, minsize=10)
        for i in range(20):
            self.grid_columnconfigure(i, weight=1, minsize=6)
        button_add = ttk.Button(self,text='+',command=self.add,width=1)
        button_add.grid(row=20, column=1,padx=(0, 30), pady=5)
        button_mins = ttk.Button(self,text='-',command=self.delete,width=1)
        button_mins.grid(row=20, column=1,padx=(30, 0), pady=5)
        # scrollable tabs
        self._listbox = tk.Listbox(self, width=2, background='white', activestyle='none',
                                   highlightthickness=0, relief='raised', selectborderwidth=6)
        scroll = ttk.Scrollbar(self, orient='vertical', command=self._listbox.yview)
        self._listbox.configure(yscrollcommand=scroll.set)

        self._current_param = None
        self._current_param_adv = None

        scroll.grid(row=0, column=0,rowspan=19, sticky='ns')
        self.grid_columnconfigure(0, weight=1, minsize=15)
        self._listbox.grid(row=0, column=1,rowspan=19, sticky='nsw')
        self.grid_columnconfigure(1, weight=1, minsize=100)
        # binding to display the selected tab
        self._listbox.bind('<<ListboxSelect>>', self.show_tab)
        self.last_select=0

        Label(self,text="input:").grid(row=4, column=3, sticky='w')
        self.grid_columnconfigure(3, weight=1, minsize=50)
        self.file_path = StringVar()
        self.file_path.trace('w', lambda *_,var=self.file_path: limitSizeDay(*_,varr=var,lenn=800))
        entry_0=Entry(self,textvariable=self.file_path)
        entry_0.grid(row=4, column=4, columnspan=15, ipady=6, sticky='we')
        button_select=tkinter.Button(self,text='select',command=lambda:select_file(self.file_path),width=5,height=1)
        button_select.grid(row=4, column=19,  sticky='w', padx=(5,5))
        self.grid_columnconfigure(19, weight=1, minsize=60)


        #boot_flags
        Label(self,text="boot flag:").grid(row=6, column=3, columnspan=2, pady=10, sticky='w')
        self.grid_columnconfigure(4, weight=1, minsize=60)
        self.boot_flags = StringVar()
        self.boot_flags.set('SCPU')
        self.boot_flags_list = ['SCPU','MCPU']
        combobox_boot_flags = ttk.Combobox(
            master=self,
                height=2,
                width=20,
                state='readonly',
                cursor='arrow',
                font=('', 10),
                textvariable=self.boot_flags,
                values=self.boot_flags_list,
                )
        combobox_boot_flags.current(0)
        combobox_boot_flags.grid(row=6, column=5, columnspan=3,   pady=10, sticky='w')
        self.grid_columnconfigure(5, weight=1, minsize=120)

        #payload_type
        Label(self,text="payload type:").grid(row=8, column=3, columnspan=2, pady=10, sticky='w')
        self.payload_type = StringVar()
        self.payload_type.set('FIRMWARE')
        self.payload_type_list = ['PUBKEY_RSA', 'PUBKEY_ECC', 'DDR', 'D2D', 'BOOTLOADER',
                                    'KERNEL', 'ROOTFS','APP','FIRMWARE','PATCH','LOADABLE_SRVC']
        combobox_payload_type= ttk.Combobox(
            master=self,
            height=11,
            width=20,
            state='readonly',
            cursor='arrow',
            font=('', 10),
            textvariable=self.payload_type,
            values=self.payload_type_list,
            )
        combobox_payload_type.current(8)
        combobox_payload_type.grid(row=8, column=5, columnspan=3,   pady=10, sticky='w')


        #label frame
        group = tk.LabelFrame(self, text='advanced options', width=190, height=80)
        group.grid(row=18, column=18,padx=(30, 0),rowspan=2, columnspan=3, pady=5, sticky='nswe')
        self.grid_rowconfigure(18, weight=1, minsize=60)
        self.grid_columnconfigure(18, weight=1, minsize=100)
        self.grid_columnconfigure(19, weight=1, minsize=60)
        self.checkbox_var =  tk.IntVar()
        checkbox = tk.Checkbutton(group, text='Enable', variable=self.checkbox_var)
        checkbox.grid(row=1, column=0,pady=10, sticky='w')
        #button expand
        self.button_exp=tk.Button(group,text='>>',command=self.expand_param_adv,
                        font=("Helvetica", 14), width=3, anchor='e',relief='flat')
        self.button_exp.grid(row=1, column=3, sticky='e')
        self.exp_window_init()


    def add(self): # add tab
        if self._current_param is not None:
            self.save_params()
        self.label_cnt = self.label_cnt + 1
        label = 'payload %i' % self.label_cnt
        self._listbox.insert('end', label)  # add label listbox
        # resize listbox to be large enough to show all tab labels
        self._listbox.configure(width=max(self._listbox.cget('width'), len(label)))
        new_param=dict()
        new_param['id'] = self.label_cnt
        self.init_param(new_param)
        self._current_param = new_param
        param_list.append(new_param)
        new_param_adv=dict()
        new_param_adv['enable'] = 'false'
        self.init_param_adv(new_param_adv)
        self._current_param_adv = new_param_adv
        param_adv_list.append(new_param_adv)
        self._listbox.selection_clear(0, 'end')
        self._listbox.selection_set('end')
        self._listbox.see('end')
        self.last_select = self._listbox.curselection()[0]
        self.show_params()

    def delete(self):
        if (self.label_cnt > 1):
            self.label_cnt = self.label_cnt - 1
        else:
            return
        param_list.pop()
        param_adv_list.pop()
        self._listbox.delete('end')

        self._listbox.selection_clear(0, 'end')
        self._listbox.selection_set('end')
        self._listbox.see('end')
        self.last_select = self._listbox.curselection()[0]

        self._current_param = param_list[self.label_cnt - 1]
        self._current_param_adv = param_adv_list[self.label_cnt - 1]
        self.show_params()

    def show_tab(self, event):
        if self._current_param is not None:
            self.save_params()
        try:
            self._current_param = param_list[self._listbox.curselection()[0]]
            self._current_param_adv = param_adv_list[self._listbox.curselection()[0]]
            self.last_select = self._listbox.curselection()[0]
        except IndexError:
            self._listbox.selection_set(self.last_select)
            return
        if self._current_param is not None:
            self.show_params()

    def init_param(self, param):
        param['in']=""
        param['boot_flags']="SCPU"
        param['payload_type']="FIRMWARE"

    def init_param_adv(self, param_adv):
        param_adv['enable']='false'
        param_adv['sign_algorithm']='plaintext'
        param_adv['keyid']='00'
        param_adv['version']='00000001'
        param_adv['load_addr']='00000000'
        param_adv['entry_addr']='00000000'
        param_adv['payload_flags']='plaintext'
        param_adv['digest_mthd']='SHA'
        param_adv['encrypted_mthd']='plaintext'
        param_adv['devid']='0000000000000000'
        param_adv['vid']='00'
        param_adv['lang']='656e67'
        param_adv['mid']='0000000000000000'
        param_adv['params']='00000000000000000000000000000000'
        param_adv['link_addr']='00000000'
        param_adv['dl_load_addr']='00000000'
        param_adv['dl_init_ofs']='00000000'
        param_adv['dl_destory_ofs']='00000000'
        param_adv['dl_ioctl_ofs']='00000000'
        param_adv['dl_load_flags']='00000000'
        param_adv['dl_irq_num']='00000000'
        param_adv['dl_irq_ofs']='00000000'

    def show_params(self):
        self.file_path.set(self._current_param['in'])
        self.boot_flags.set(self._current_param['boot_flags'])
        self.payload_type.set(self._current_param['payload_type'])
        if (self._current_param_adv['enable']=='true'):
            self.checkbox_var.set(1)
        else:
            self.checkbox_var.set(0)
        self.sign_algorithm.set(self._current_param_adv['sign_algorithm'])
        self.keyid.set(self._current_param_adv['keyid'])
        self.version.set(self._current_param_adv['version'])
        self.load_addr.set(self._current_param_adv['load_addr'])
        self.entry_addr.set(self._current_param_adv['entry_addr'])
        self.payload_flags.set(self._current_param_adv['payload_flags'])
        self.digest_mthd.set(self._current_param_adv['digest_mthd'])
        self.encrypted_mthd.set(self._current_param_adv['encrypted_mthd'])
        self.devid.set(self._current_param_adv['devid'])
        self.vid.set(self._current_param_adv['vid'])
        self.lang.set(self._current_param_adv['lang'])
        self.mid.set(self._current_param_adv['mid'])
        self.params.set(self._current_param_adv['params'])
        self.link_addr.set(self._current_param_adv['link_addr'])
        self.dl_load_addr.set(self._current_param_adv['dl_load_addr'])
        self.dl_init_ofs.set(self._current_param_adv['dl_init_ofs'])
        self.dl_destory_ofs.set(self._current_param_adv['dl_destory_ofs'])
        self.dl_ioctl_ofs.set(self._current_param_adv['dl_ioctl_ofs'])
        self.dl_load_flags.set(self._current_param_adv['dl_load_flags'])
        self.dl_irq_num.set(self._current_param_adv['dl_irq_num'])
        self.dl_irq_ofs.set(self._current_param_adv['dl_irq_ofs'])

    def save_params(self):
        self._current_param['in']=self.file_path.get()
        self._current_param['boot_flags']=self.boot_flags.get()
        self._current_param['payload_type']=self.payload_type.get()
        if (self.checkbox_var.get() == 1):
            self._current_param_adv['enable']='true'
        else:
            self._current_param_adv['enable']='false'
        self._current_param_adv['sign_algorithm']=self.sign_algorithm.get()
        self._current_param_adv['keyid']=self.keyid.get()
        self._current_param_adv['version']=self.version.get()
        self._current_param_adv['load_addr']=self.load_addr.get()
        self._current_param_adv['entry_addr']=self.entry_addr.get()
        self._current_param_adv['payload_flags']=self.payload_flags.get()
        self._current_param_adv['digest_mthd']=self.digest_mthd.get()
        self._current_param_adv['encrypted_mthd']=self.encrypted_mthd.get()
        self._current_param_adv['devid']=self.devid.get()
        self._current_param_adv['vid']=self.vid.get()
        self._current_param_adv['lang']=self.lang.get()
        self._current_param_adv['mid']=self.mid.get()
        self._current_param_adv['params']=self.params.get()
        self._current_param_adv['link_addr']=self.link_addr.get()
        self._current_param_adv['dl_load_addr']=self.dl_load_addr.get()
        self._current_param_adv['dl_init_ofs']=self.dl_init_ofs.get()
        self._current_param_adv['dl_destory_ofs']=self.dl_destory_ofs.get()
        self._current_param_adv['dl_ioctl_ofs']=self.dl_ioctl_ofs.get()
        self._current_param_adv['dl_load_flags']=self.dl_load_flags.get()
        self._current_param_adv['dl_irq_num']=self.dl_irq_num.get()
        self._current_param_adv['dl_irq_ofs']=self.dl_irq_ofs.get()

    def restore_from_file(self, count):
        self.book_reset()
        self._current_param = param_list[0]
        self._current_param_adv = param_adv_list[0]
        self.label_cnt = count
        for i in range(count):
            label = 'payload %i' % (i + 1)
            self._listbox.insert('end', label)  # add label listbox
            self._listbox.configure(width=max(self._listbox.cget('width'), len(label)))
        self._listbox.selection_clear(0, 'end')
        self._listbox.selection_set(0)
        self._listbox.see(0)
        self.show_params()

    def book_reset(self):
        self._current_param.clear()
        self._current_param_adv.clear()
        self.label_cnt = 0
        self.file_path.set('')
        self.boot_flags.set('')
        self.payload_type.set('')
        self.sign_algorithm.set('')
        self.keyid.set('')
        self.version.set('')
        self.load_addr.set('')
        self.entry_addr.set('')
        self.payload_flags.set('')
        self.digest_mthd.set('')
        self.encrypted_mthd.set('')
        self.devid.set('')
        self.vid.set('')
        self.lang.set('')
        self.mid.set('')
        self.params.set('')
        self.link_addr.set('')
        self.dl_load_addr.set('')
        self.dl_init_ofs.set('')
        self.dl_destory_ofs.set('')
        self.dl_ioctl_ofs.set('')
        self.dl_load_flags.set('')
        self.dl_irq_num.set('')
        self.dl_irq_ofs.set('')
        self._listbox.delete(0, 'end')
        self.last_select = 0

    def expand_param_adv(self):
        if ( self.button_exp.cget('text') == '>>'):
            self.button_exp.config(text='<<')
            exp_window_x = root_window.winfo_x() + root_window.winfo_width() + 6
            exp_window_y = root_window.winfo_y() - 70
            self.exp_window.geometry(f'900x600+{exp_window_x}+{exp_window_y}')
            self.exp_window.deiconify()
        else:
            self.button_exp.config(text='>>')
            self.exp_window.withdraw()
            return
    def exp_window_on_closing(self):
        self.button_exp.config(text='>>')
        self.exp_window.withdraw()
        return
    def exp_window_on_minimize(self, event=None):
        self.button_exp.config(text='>>')
        self.exp_window.withdraw()
        return


    def exp_window_init(self):
        global encrypt_enable
        exp_window_x = root_window.winfo_x() + root_window.winfo_width() + 6
        exp_window_y = root_window.winfo_y() - 70
        self.exp_window = tk.Toplevel(self)
        add_window = self.exp_window
        add_window.title('advanced options')
        add_window.geometry(f'900x600+{exp_window_x}+{exp_window_y}')
        add_window.resizable(0,0)
        #add_window.overrideredirect(1)
        self.exp_window.withdraw()
        self.exp_window.protocol("WM_DELETE_WINDOW", self.exp_window_on_closing)
        self.exp_window.bind("<Unmap>", self.exp_window_on_minimize)

        rel_x_1=0.03
        rel_x_2=0.17
        rel_x_3=0.45
        rel_x_4=0.6
        rel_y_1=0.08
        i=1

        #sign_algorithm
        Label(add_window,text="sign_algorithm:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.sign_algorithm = StringVar()
        self.sign_algorithm.set('plaintext')
        self.sign_algorithm_list = ['plaintext','RSA', 'ECDSA']
        combobox = ttk.Combobox(
            master=add_window,
            height=3,
            width=20,
            cursor='arrow',
            font=('', 10),
            textvariable=self.sign_algorithm,
            values=self.sign_algorithm_list,
            state='readonly' if encrypt_enable else 'disable',
            )
        combobox.current(0)
        combobox.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #keyid
        Label(add_window,text="keyid:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.keyid = StringVar()
        self.keyid.set('00')
        self.keyid.trace('w', lambda *_,var=self.keyid: limitSizeDay(*_,varr=var,lenn=2))
        entry_1=Entry(add_window, textvariable=self.keyid,
            state='normal' if encrypt_enable else 'disable')
        entry_1.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #version
        Label(add_window,text="version:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.version = StringVar()
        self.version.set('00000001')
        self.version.trace('w', lambda *_,var=self.version: limitSizeDay(*_,varr=var,lenn=8))
        entry_2=Entry(add_window,textvariable=self.version)
        entry_2.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #load_addr
        Label(add_window,text="load_addr:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.load_addr = StringVar()
        self.load_addr.set('00000000')
        self.load_addr.trace('w', lambda *_,var=self.load_addr: limitSizeDay(*_,varr=var,lenn=16))
        entry_3=Entry(add_window,textvariable=self.load_addr)
        entry_3.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #entry_addr
        Label(add_window,text="entry_addr:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.entry_addr = StringVar()
        self.entry_addr.set('00000000')
        self.entry_addr.trace('w', lambda *_,var=self.entry_addr: limitSizeDay(*_,varr=var,lenn=16))
        entry_4=Entry(add_window,textvariable=self.entry_addr)
        entry_4.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #payload_flags
        Label(add_window,text="payload_flags:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.payload_flags = StringVar()
        self.payload_flags.set('plaintext')
        self.payload_flags_list = ['plaintext', 'encrypted']
        combobox_payload_flags = ttk.Combobox(
            master=add_window,
                height=2,
                width=20,
                state='readonly',
                cursor='arrow',
                font=('', 10),
                textvariable=self.payload_flags,
                values=self.payload_flags_list,
                )
        combobox_payload_flags.current(0)
        combobox_payload_flags.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #digest_mthd
        Label(add_window,text="digest_mthd:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.digest_mthd = StringVar()
        self.digest_mthd.set('SHA')
        self.digest_mthd_list = ['SHA', 'SM3']
        combobox_digest_mthd = ttk.Combobox(
            master=add_window,
                height=2,
                width=20,
                cursor='arrow',
                font=('', 10),
                textvariable=self.digest_mthd,
                values=self.digest_mthd_list,
                state='readonly' if encrypt_enable else 'disable',
                )
        combobox_digest_mthd.current(0)
        combobox_digest_mthd.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')

        i+=1
        #encrypted_mthd
        Label(add_window,text="encrypted_mthd:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.encrypted_mthd = StringVar()
        self.encrypted_mthd.set('plaintext')
        self.encrypted_mthd_list = ['plaintext','AES', 'SM4']
        combobox_encrypted_mthd = ttk.Combobox(
            master=add_window,
                height=3,
                width=20,
                cursor='arrow',
                font=('', 10),
                textvariable=self.encrypted_mthd,
                values=self.encrypted_mthd_list,
                state='readonly' if encrypt_enable else 'disable',
                )
        combobox_encrypted_mthd.current(0)
        combobox_encrypted_mthd.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #devid
        Label(add_window,text="devid:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.devid = StringVar()
        self.devid.set('0000000000000000')
        self.devid.trace('w', lambda *_,var=self.devid: limitSizeDay(*_,varr=var,lenn=16))
        entry_5=Entry(add_window,textvariable=self.devid)
        entry_5.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        #vid
        Label(add_window,text="vid:").place(relx=rel_x_1,rely=rel_y_1*i,anchor='sw')
        self.vid = StringVar()
        self.vid.set('00')
        self.vid.trace('w', lambda *_,var=self.vid: limitSizeDay(*_,varr=var,lenn=2))
        entry_6=Entry(add_window,textvariable=self.vid)
        entry_6.place(relx=rel_x_2,rely=rel_y_1*i,anchor='sw')
        i+=1

        left_max_i=i

        i=1
        #lang
        Label(add_window,text="lang:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.lang = StringVar()
        self.lang.set('656e67')
        self.lang.trace('w', lambda *_,var=self.lang: limitSizeDay(*_,varr=var,lenn=6))
        entry_7=Entry(add_window,textvariable=self.lang)
        entry_7.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #mid
        Label(add_window,text="mid:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.mid = StringVar()
        self.mid.set('0000000000000000')
        self.mid.trace('w', lambda *_,var=self.mid: limitSizeDay(*_,varr=var,lenn=16))
        entry_8=Entry(add_window,textvariable=self.mid)
        entry_8.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #params
        Label(add_window,text="params:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.params = StringVar()
        self.params.set('00000000000000000000000000000000')
        self.params.trace('w', lambda *_,var=self.params: limitSizeDay(*_,varr=var,lenn=32))
        entry_9=Entry(add_window,textvariable=self.params)
        entry_9.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw',width=330,height=30)
        i+=1

        #link_addr
        Label(add_window,text="link_addr:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.link_addr = StringVar()
        self.link_addr.set('00000000')
        self.link_addr.trace('w', lambda *_,var=self.link_addr: limitSizeDay(*_,varr=var,lenn=16))
        entry_10=Entry(add_window,textvariable=self.link_addr)
        entry_10.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #dl_load_addr
        Label(add_window,text="dl_load_addr:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.dl_load_addr = StringVar()
        self.dl_load_addr.set('00000000')
        self.dl_load_addr.trace('w', lambda *_,var=self.dl_load_addr: limitSizeDay(*_,varr=var,lenn=8))
        entry_11=Entry(add_window,textvariable=self.dl_load_addr)
        entry_11.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #dl_init_ofs
        Label(add_window,text="dl_init_ofs:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.dl_init_ofs = StringVar()
        self.dl_init_ofs.set('00000000')
        self.dl_init_ofs.trace('w', lambda *_,var=self.dl_init_ofs: limitSizeDay(*_,varr=var,lenn=8))
        entry_12=Entry(add_window,textvariable=self.dl_init_ofs)
        entry_12.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #dl_destory_ofs
        Label(add_window,text="dl_destory_ofs:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.dl_destory_ofs = StringVar()
        self.dl_destory_ofs.set('00000000')
        self.dl_destory_ofs.trace('w', lambda *_,var=self.dl_destory_ofs: limitSizeDay(*_,varr=var,lenn=8))
        entry_13=Entry(add_window,textvariable=self.dl_destory_ofs)
        entry_13.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #dl_ioctl_ofs
        Label(add_window,text="dl_ioctl_ofs:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.dl_ioctl_ofs = StringVar()
        self.dl_ioctl_ofs.set('00000000')
        self.dl_ioctl_ofs.trace('w', lambda *_,var=self.dl_ioctl_ofs: limitSizeDay(*_,varr=var,lenn=8))
        entry_14=Entry(add_window,textvariable=self.dl_ioctl_ofs)
        entry_14.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #dl_load_flags
        Label(add_window,text="dl_load_flags:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.dl_load_flags = StringVar()
        self.dl_load_flags.set('00000000')
        self.dl_load_flags.trace('w', lambda *_,var=self.dl_load_flags: limitSizeDay(*_,varr=var,lenn=8))
        entry_15=Entry(add_window,textvariable=self.dl_load_flags)
        entry_15.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #dl_irq_num
        Label(add_window,text="dl_irq_num:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.dl_irq_num = StringVar()
        self.dl_irq_num.set('00000000')
        self.dl_irq_num.trace('w', lambda *_,var=self.dl_irq_num: limitSizeDay(*_,varr=var,lenn=8))
        entry_16=Entry(add_window,textvariable=self.dl_irq_num)
        entry_16.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')
        i+=1

        #dl_irq_ofs
        Label(add_window,text="dl_irq_ofs:").place(relx=rel_x_3,rely=rel_y_1*i,anchor='sw')
        self.dl_irq_ofs = StringVar()
        self.dl_irq_ofs.set('00000000')
        self.dl_irq_ofs.trace('w', lambda *_,var=self.dl_irq_ofs: limitSizeDay(*_,varr=var,lenn=8))
        entry_17=Entry(add_window,textvariable=self.dl_irq_ofs)
        entry_17.place(relx=rel_x_4,rely=rel_y_1*i,anchor='sw')

def get_param_list_string():
    global of_path
    i = 0
    param_s=' out='+of_path.get()+'\r\n '
    for p in param_list:
        param_s=param_s+'\r\n '+ '{\r\n '
        param_s=param_s+'in='+p['in']+'\r\n '
        param_s=param_s+'boot_flags='+p['boot_flags']+'\r\n '
        param_s=param_s+'payload_type='+p['payload_type']+'\r\n '
        pa=param_adv_list[i]
        if (pa['enable'] == 'true'):
            param_s=param_s+'sign_algorithm='+pa['sign_algorithm'] + '\r\n '
            param_s=param_s+'keyid='+pa['keyid'] + '\r\n '
            param_s=param_s+'version='+pa['version'] + '\r\n '
            param_s=param_s+'load_addr='+pa['load_addr'] + '\r\n '
            param_s=param_s+'entry_addr='+pa['entry_addr'] + '\r\n '
            param_s=param_s+'payload_flags='+pa['payload_flags'] + '\r\n '
            param_s=param_s+'digest_mthd='+pa['digest_mthd'] + '\r\n '
            param_s=param_s+'encrypted_mthd='+pa['encrypted_mthd'] + '\r\n '
            param_s=param_s+'devid='+pa['devid'] + '\r\n '
            param_s=param_s+'vid='+pa['vid'] + '\r\n '
            param_s=param_s+'lang='+pa['lang'] + '\r\n '
            param_s=param_s+'mid='+pa['mid'] + '\r\n '
            param_s=param_s+'params='+pa['params'] + '\r\n '
            param_s=param_s+'link_addr='+pa['link_addr'] + '\r\n '
            param_s=param_s+'dl_load_addr='+pa['dl_load_addr'] + '\r\n '
            param_s=param_s+'dl_init_ofs='+pa['dl_init_ofs'] + '\r\n '
            param_s=param_s+'dl_destory_ofs='+pa['dl_destory_ofs'] + '\r\n '
            param_s=param_s+'dl_ioctl_ofs='+pa['dl_ioctl_ofs'] + '\r\n '
            param_s=param_s+'dl_load_flags='+pa['dl_load_flags'] + '\r\n '
            param_s=param_s+'dl_irq_num='+pa['dl_irq_num'] + '\r\n '
            param_s=param_s+'dl_irq_ofs='+pa['dl_irq_ofs'] + '\r\n '
        param_s=param_s+'}\r\n'
        i = i + 1
    return param_s

def parse_config_file(config_file):
    global of_path
    global nb
    global param_name
    param_list.clear()
    param_adv_list.clear()

    f = open(config_file,'r',encoding='utf-8')
    param_left=0
    param_right=0
    line_list=[]
    tmp=0
    for line in f.readlines():
        tmp+=1
        if '{' in line:
            param_left+=1
            line_list.append(tmp)
        if '}' in line:
            param_right+=1
            line_list.append(tmp)

    if param_left==param_right:
        for i in range(param_left):
            new_param=dict()
            nb.init_param(new_param)
            param_list.append(new_param)
            new_param_adv=dict()
            nb.init_param_adv(new_param_adv)
            param_adv_list.append(new_param_adv)
    else:
        tk.messagebox.showwarning(title='warning', message='config file parase error!')
        f.close()
        return -1

    f.seek(0)
    tmp=0
    flag=1
    count=0
    payload_count=int(len(line_list)/2)
    for line in f.readlines():
        tmp+=1
        if tmp<line_list[flag-1]:
            param_left=line[1:line.rfind('=')].rstrip()
            if param_left=='out':
                param_right=line[line.rfind('=')+1:].rstrip()
                of_path.set(param_right)

        if (tmp>line_list[flag-1])&(tmp<line_list[flag]):
            param_left=line[1:line.rfind('=')].rstrip()
            param_right=line[line.rfind('=')+1:].rstrip()
            if param_left!='':
                if param_left in param_name:
                    param_list[count][param_left]=param_right
                elif param_left in param_adv_name:
                    param_adv_list[count][param_left]=param_right
                    param_adv_list[count]['enable']='true'
        if tmp==line_list[flag]:
            if len(line_list)-flag>=2:
                count+=1
                flag+=2
    f.close()
    return payload_count

def check_param_list_is_valid():
    global of_path
    param_list_len = len(param_list)
    if param_list_len < 1:
        tk.messagebox.showinfo(title='error', message='no payload!')
        return -1
    for p in param_list:
        if p['in'] == '':
            tk.messagebox.showinfo(title='error', message='no input file')
            return -1
        if not os.path.exists(p['in']):
            tk.messagebox.showinfo(title='error', message=f'input:{p["in"]} is not exists!')
            return -1
        if not os.access(p['in'], os.R_OK):
            tk.messagebox.showinfo(title='error', message=f'input:{p["in"]} is not readable!')
            return -1
    if of_path.get() == '':
        tk.messagebox.showinfo(title='error', message='no output file')
        return -1
    of_dir_path = os.path.dirname(of_path.get())
    if not os.path.exists(of_dir_path):
        tk.messagebox.showinfo(title='error', message=f'output path:{of_dir_path} is not exists!')
        return -1
    if not os.access(of_dir_path, os.W_OK):
        tk.messagebox.showinfo(title='error', message=f'output directory:{of_dir_path} is not writable!')
        return -1
    return 0

def sign():
    global nb
    nb.save_params()

    if not os.access(current_path, os.W_OK):
        tk.messagebox.showinfo(title='error', message=f'current directory:{current_path} not writable!')
        return

    if plat == 'windows':
        config_file_path=current_path+'\\config.txt'
    elif plat == 'linux':
        config_file_path=current_path+'/config.txt'

    if check_param_list_is_valid() < 0:
        return
    param_s = get_param_list_string()
    with open(config_file_path,"w",encoding="utf-8") as f:
            f.write(param_s)
    ret=call_sign_exe()
    if ret == 0:
        tk.messagebox.showinfo(title='note', message='sign done!')

def menu_new():
    global nb
    global of_path
    param_list.clear()
    param_adv_list.clear()
    nb.book_reset()
    nb.add()
    menu_open_file = ''
    of_path.set('')

def menu_open():
    global menu_open_file
    global nb
    config_file = filedialog.askopenfilename()
    if config_file:
        of_path.set('')
        payload_count = parse_config_file(config_file)
        if(payload_count < 0):
            return
        nb.restore_from_file(payload_count)
        menu_open_file = config_file

def menu_save():
    global nb
    global of_path
    nb.save_params()
    if (len(menu_open_file) > 0):
        try:
            f = open(menu_open_file,'w',encoding='utf-8')
            param_s = get_param_list_string()
            f.write(param_s)
            f.close()
            tk.messagebox.showinfo(title='note', message='save done!')
        except FileNotFoundError:
            tk.messagebox.showinfo(title='error', message='file not found!')
        except PermissionError:
            tk.messagebox.showinfo(title='error', message='permission error!')
    else:
        menu_save_as()

def menu_save_as():
    global nb
    global of_path
    nb.save_params()
    file = filedialog.asksaveasfile(mode='w',defaultextension=".txt")
    if file:
        param_s = get_param_list_string()
        file.write(param_s)
        file.close()
        tk.messagebox.showinfo(title='note', message='save done!')

def menu_exit():
    root_window.destroy()

def create_workspace():
    global nb
    global of_path
    nb.add()
    nb.pack(expand=True, fill='both', pady=(0,10))

    s=ttk.Style()
    s.configure('w.TSeparator', background='white')
    sparator = ttk.Separator(root_window, orient="horizontal", style='w.TSeparator')
    sparator.pack(fill='x', pady=(0,10))

    Label(root_window,text="output:").pack(side= 'left', padx=(20,0), pady=(0,10))
    of_path.trace('w', lambda *_,var=of_path: limitSizeDay(*_,varr=var,lenn=2000))
    params_of=Entry(root_window,textvariable=of_path)
    params_of.pack(side= 'left', padx=0, pady=(0,10),ipadx=100, ipady=6)

    button_sign = ttk.Button(root_window,text='select',command=lambda:select_save_file(of_path),width=5)
    button_sign.pack(side= 'left',padx=(4,10), pady=(0,10))

    button_sign = ttk.Button(root_window,text='sign',command=sign,width=5)
    button_sign.pack(side= 'right', pady=(0,10))

root_window = tkinter.Tk()
get_sign_exe_version()
root_window.title('NSIGN TOOL ' + nsign_version)
root_window.geometry('600x500')
root_window.resizable(False, False)

menu_main = Menu(root_window)
menu_sub = Menu(menu_main, tearoff=0)
menu_sub.add_command(label='New', command=menu_new)
menu_sub.add_command(label='Open...', command=menu_open)
menu_sub.add_separator()

menu_sub.add_command(label='Save', command=menu_save)
menu_sub.add_command(label='Save As...', command=menu_save_as)
menu_sub.add_separator()

menu_sub.add_command(label='Genkey', command=genkey)
menu_sub.add_separator()

menu_sub.add_command(label='Exit', command=menu_exit)

menu_main.add_cascade(label='Menu', menu=menu_sub)
root_window.configure(menu=menu_main, relief='sunken')

of_path = StringVar()
nb = VertNotebook(root_window)
create_workspace()
root_window.mainloop()
