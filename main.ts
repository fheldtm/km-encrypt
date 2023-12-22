import * as crypto from 'crypto';
import {
	App,
	MarkdownView,
	Modal,
	Notice,
	Plugin
} from 'obsidian';

const encrypt = (text: string, password: string): string => {
	const algorithm = 'aes-256-ctr';
	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv(algorithm, crypto.createHash('sha256').update(password).digest(), iv);
	const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
	return iv.toString('hex') + ':' + encrypted.toString('hex');
}

const decrypt = (hash: string, password: string): string => {
	try {
		const algorithm = 'aes-256-ctr';
		const textParts = hash.split(':');
		const iv = Buffer.from(textParts.shift() || '', 'hex');
		const encryptedText = Buffer.from(textParts.join(':'), 'hex');
		const decipher = crypto.createDecipheriv(algorithm, crypto.createHash('sha256').update(password).digest(), iv);
		const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
		return decrypted.toString();
	} catch(e) {
		return '';
	}
}

const currentNoteMeta = {
	isEncrypt: false,
	encryptedAt: '',
	encryptedTitle: '',
	encryptPassword: '',
	update: () => {}
}

export default class MyPlugin extends Plugin {
	async onload() {
		// This creates an icon in the left ribbon.
		const encryptRibbonIconEl = this.addRibbonIcon('lock', 'Encrypt Note', (evt: MouseEvent) => {
			new FirstEncryptModal(this.app).open();
		});
		// Perform additional things with the ribbon
		encryptRibbonIconEl.addClass('my-plugin-ribbon-class');

		// This creates an icon in the left ribbon.
		const decryptRibbonIconEl = this.addRibbonIcon('hash', 'Decrypt Note', (evt: MouseEvent) => {
			new DecryptPasswordModal(this.app).open();
		});
		// Perform additional things with the ribbon
		decryptRibbonIconEl.addClass('my-plugin-ribbon-class');

		// This adds a status bar item to the bottom of the app. Does not work on mobile apps.
		const statusBarItemEl = this.addStatusBarItem();
		statusBarItemEl.setText('Status Bar Text');

		this.addCommand({
			id: 'Encrypt Note',
			name: 'Encrypt Note',
			callback: () => {
				new FirstEncryptModal(this.app).open();
			}
		})

		this.addCommand({
			id: 'Decrypt Note',
			name: 'Decrypt Note',
			callback: () => {
				new DecryptPasswordModal(this.app).open();
			}
		})

		this.registerEvent(
			this.app.workspace.on('active-leaf-change', (e) => {
				new DecryptPasswordModal(this.app).open();
			})
		);
	}

	onunload() {
	}
}

class EncryptOrDecryptModal extends Modal {
	constructor(app: App) {
		super(app)
	}

	checkNoteIsEncrypted(): boolean {
		const activeLeaf = this.app.workspace.getLeaf();
		if (!activeLeaf) {
			return false;
		}

		const view = activeLeaf.view;
		if (!(view instanceof MarkdownView)) {
			return false;
		}

		const doc = view.editor.getDoc();
		const noteContent = doc.getValue();

		// 위에서 2, 4줄(meta data)을 확인
		const lines = noteContent?.split('\n');
		const isEncrypt = lines?.[1]?.includes('km-encrypted: true') || false;

		return isEncrypt;
	}

	getNoteEncryptedInfo() {
		const failResult = {
			isEncrypt: false,
			encryptedAt: '',
			encryptedTitle: ''
		};

		const activeLeaf = this.app.workspace.getLeaf();
		if (!activeLeaf) {
			return failResult;
		}

		const view = activeLeaf.view;
		if (!(view instanceof MarkdownView)) {
			return failResult;
		}

		const doc = view.editor.getDoc();
		const noteContent = doc.getValue();

		// 위에서 2, 4줄(meta data)을 확인
		const lines = noteContent.split('\n');
		const isEncrypt = lines?.[1]?.includes('km-encrypted: true') || false;
		if (isEncrypt === false) {
			return failResult;
		}

		const encryptedAt = lines?.[2]?.split('encryptedAt: ')?.[1] || '';
		const encryptedTitle = lines?.[3]?.split('title: ')?.[1] || '';

		return {
			isEncrypt,
			encryptedAt,
			encryptedTitle
		};
	}

	async EncryptNote(encryptKey: string) {
		// Get the current active leaf
		const activeLeaf = this.app.workspace.getLeaf();
		if (!activeLeaf) {
			this.close();
			return;
		}

		// If there's an active leaf, get its content
		const view = activeLeaf.view;
		if (!(view instanceof MarkdownView)) {
			this.close();
			return;
		}

		const noteTitle = view.file?.basename;

		const doc = view.editor.getDoc();
		const noteContent = doc.getValue();

		const password = encryptKey;

		const encryptedTitle = encrypt(noteTitle || '', password);
		const encryptedContent = encrypt(noteContent, password);

		const now = new Date();
		const koreaTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
		const encryptInfo = {
			encryptedAt: koreaTime.toISOString(),
			title: encryptedTitle
		}
		let newNoteContent = '---\n';
		newNoteContent += `km-encrypted: true\n`;
		newNoteContent += `encryptedAt: ${encryptInfo.encryptedAt}\n`;
		newNoteContent += `title: ${encryptInfo.title}\n`;
		newNoteContent += `---\n`;
		newNoteContent += `${encryptedContent}`;

		if (view.file) {
			await this.app.vault.modify(view.file, newNoteContent);
		}
	}

	checkIsMarkdownFile() {
		const activeLeaf = this.app.workspace.getLeaf();
		if (!activeLeaf) {
			return false;
		}

		const view = activeLeaf.view;
		if (!(view instanceof MarkdownView)) {
			return false;
		}

		return true;
	}
}

class FirstEncryptModal extends EncryptOrDecryptModal {
	constructor(app: App) {
		super(app);
	}

  async onOpen() {
		if (this.checkIsMarkdownFile() === false) {
			this.close();
			return;
		}

		if (this.checkNoteIsEncrypted()) {
			new Notice('This note is already encrypted');
			this.close();
			return;
		}

    const { contentEl } = this;
    const form = contentEl.createEl("form");
    form.addClass("km-encrypt__form");

    // title
    // <p class="km-encrypt__title">Encrypt your note with a key.</p>
    form.createEl('p', {
      text: 'Encrypt your note with a key.',
      cls: 'km-encrypt__title'
    })

    // encrypt div
    const encryptInputDiv = form.createDiv();
    encryptInputDiv.addClass("km-encrypt__input");
    const encryptKeyInput = encryptInputDiv.createEl("input", { type: "password" });
    encryptKeyInput.placeholder = "Enter encryption key";

    const encryptConfirmInputDiv = form.createDiv();
    encryptConfirmInputDiv.addClass("km-encrypt__input");
    const encryptConfirmKeyInput = encryptConfirmInputDiv.createEl("input", { type: "password" });
    encryptConfirmKeyInput.placeholder = "Confirm encryption key";

    // <button type="submit">Encrypt</button>
    const submitButton = form.createEl("button", { type: "submit" });
    submitButton.textContent = "Encrypt";

		form.addEventListener('submit', async (e: SubmitEvent) => {
			e.preventDefault();
			const encryptKey = encryptKeyInput.value;
			const encryptConfirmKey = encryptConfirmKeyInput.value;

			if (encryptKey.length === 0) {
				new Notice('Key cannot be empty');
				return;
			}

			if (encryptKey !== encryptConfirmKey) {
				new Notice('Keys do not match');
				return;
			}

			this.EncryptNote(encryptKey);

			this.close();
		});
  }
}

// 해당 파일이 암호화된 파일이면 열리는 모달
class DecryptPasswordModal extends EncryptOrDecryptModal {
	passwordFailCount = 1;
	isSuccessDecrypt = false;

	constructor(app: App) {
		super(app);
	}

  async onOpen() {
		if (this.checkIsMarkdownFile() === false) {
			this.close();
			return;
		}

		// 암호화 된 파일인지 확인
		const isEncrypt = this.checkNoteIsEncrypted();
		if (isEncrypt === false) {
			this.close();
			return;
		}

		const metaInfo = this.getNoteEncryptedInfo();
		const encryptedTitle = metaInfo.encryptedTitle;

		// Get the current active leaf
		const activeLeaf = this.app.workspace.getLeaf();

		// If there's an active leaf, get its content
		if (!activeLeaf) {
			this.close();
			return;
		}

		const view = activeLeaf.view;
		if (!(view instanceof MarkdownView)) {
			this.close();
			return;
		}

		const doc = view.editor.getDoc();
		const noteContentWithMeta = doc.getValue();

    const { contentEl } = this;
    const form = contentEl.createEl("form");
    form.addClass("km-encrypt__form");

    // title
    // <p class="km-encrypt__title">Encrypt your note with a key.</p>
    form.createEl('p', {
      text: 'Input Password to Decrypt',
      cls: 'km-encrypt__title'
    })

    // encrypt div
    const decryptInputDiv = form.createDiv();
    decryptInputDiv.addClass("km-encrypt__input");
    const decryptKeyInput = decryptInputDiv.createEl("input", { type: "password" });
    decryptKeyInput.placeholder = "Enter decryption key";

    // <button type="submit">Decrypt</button>
    const submitButton = form.createEl("button", { type: "submit" });
    submitButton.textContent = "Decrypt";

		form.addEventListener('submit', async (e: SubmitEvent) => {
			e.preventDefault();
			const decryptKey = decryptKeyInput.value;

			if (decryptKey.length === 0) {
				new Notice('Key cannot be empty');
				return;
			}

			const noteTitle = view.file?.basename;

			const password = decryptKey;

			const decryptedTitle = decrypt(encryptedTitle, password);
			if (decryptedTitle !== noteTitle) {
				if (this.passwordFailCount >= 5) {
					new Notice('Password is incorrect. Please try again later.');
					this.close();
					return;
				}

				// 남은 횟수 표시 최대 5회
				new Notice(`Password is incorrect. ${5 - this.passwordFailCount} times left`);
				this.passwordFailCount += 1;
				return;
			}

			// 복호화 성공
			// 현재 열려있는 노트의 암호화 정보 저장
			currentNoteMeta.encryptedAt = metaInfo.encryptedAt;
			currentNoteMeta.encryptedTitle = metaInfo.encryptedTitle;
			currentNoteMeta.isEncrypt = metaInfo.isEncrypt;
			currentNoteMeta.encryptPassword = password;

			// 기존 메타 정보 제거
			const noteContent = noteContentWithMeta.split('\n').slice(5).join('\n');
			const decryptedContent = decrypt(noteContent, password);
			if (view.file) {	
				await this.app.vault.modify(view.file, decryptedContent);
			}

			this.isSuccessDecrypt = true;
			this.close();
		});
  }

	async onClose() {
		// 해당 파일이 암호화된 파일이 아니면 종료
		if (this.checkNoteIsEncrypted() === false) {
			return;
		}
		
		if (!this.isSuccessDecrypt) {
			// 복호화 실패 또는 취소 또는 암호화 된 파일이 아닌 경우
			const activeLeaf = this.app.workspace.getLeaf();
			// 열려있는 leaf 확인
			if (!activeLeaf) {
				return;
			}

			// 열려있는 leaf가 markdown view인지 확인
			const view = activeLeaf.view;
			if (!(view instanceof MarkdownView)) {
				return;
			}

			// 암호화 된 파일일 경우 복호화 실패 또는 취소 한 경우임
			activeLeaf.detach();
		}
	}
}