/*
index.ts
This is the main file for the Auth Inbox Email Worker.
created by: github@TooonyChen
created on: 2024 Oct 07
Last updated: 2024 Oct 07
*/

import indexHtml from './index.html';
import settingsHtml from './settings.html';
import rawEmailHtml from './raw_email.html';

export interface Env {
	// If you set another name in wrangler.toml as the value for 'binding',
	// replace "DB" with the variable name you defined.
	DB: D1Database;
	FrontEndAdminID: string;
	FrontEndAdminPassword: string;
	barkTokens: string;
	barkUrl: string;
	GoogleAPIKey: string;
	UseBark: string;
}

async function checkAuth(env: Env, authHeader: string | null): Promise<boolean> {
	if (!authHeader || !authHeader.startsWith('Basic ')) {
		return false;
	}

	const base64Credentials = authHeader.substring('Basic '.length);
	const decodedCredentials = atob(base64Credentials);
	const [username, password] = decodedCredentials.split(':');

	return username === env.FrontEndAdminID && password === env.FrontEndAdminPassword;
}

function createUnauthorizedResponse(): Response {
	return new Response('Unauthorized', {
		status: 401,
		headers: {
			'WWW-Authenticate': 'Basic realm="User Visible Realm"',
		},
	});
}

async function checkEmailAccess(email: string, env: Env, authHeader: string | null): Promise<boolean> {
	const { results } = await env.DB.prepare('SELECT is_private FROM email_settings WHERE email = ?').bind(email).all();

	// If no settings found or is private, require auth
	if (!results || results.length === 0 || results[0].is_private) {
		return await checkAuth(env, authHeader);
	}

	// If public, allow access
	return true;
}

// Add helper function to extract email parts
function parseMultipartEmail(rawEmail: string): { text: string; html: string } {
	const result = { text: '', html: '' };

	// Try to find the boundary
	const boundaryMatch = rawEmail.match(/boundary="([^"]+)"/);
	if (!boundaryMatch) {
		return result;
	}

	const boundary = boundaryMatch[1];
	const parts = rawEmail.split('--' + boundary);

	for (const part of parts) {
		if (part.includes('Content-Type: text/plain')) {
			const content = part
				.split(/\r?\n\r?\n/)
				.slice(1)
				.join('\r\n\r\n');
			result.text = content.trim();
		} else if (part.includes('Content-Type: text/html')) {
			const content = part
				.split(/\r?\n\r?\n/)
				.slice(1)
				.join('\r\n\r\n');
			result.html = content.trim();
		}
	}

	// Clean up encoded characters
	if (result.text) {
		result.text = result.text.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, p1) => String.fromCharCode(parseInt(p1, 16)));
	}

	if (result.html) {
		result.html = result.html.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, p1) => String.fromCharCode(parseInt(p1, 16)));
	}

	return result;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname;
		const authHeader = request.headers.get('Authorization');

		try {
			// Handle settings page (always requires auth)
			if (path === '/settings') {
				// Check auth for settings page
				if (!(await checkAuth(env, authHeader))) {
					return createUnauthorizedResponse();
				}

				if (request.method === 'POST') {
					const formData = await request.formData();
					const email = formData.get('email')?.toString();
					const isPrivate = formData.get('is_private') === 'on' ? 1 : 0;

					if (email) {
						await env.DB.prepare(
							`INSERT OR REPLACE INTO email_settings (email, is_private) 
							 VALUES (?, ?)`
						)
							.bind(email, isPrivate)
							.run();
					}
				}

				// Fetch all settings
				const { results: settings } = await env.DB.prepare('SELECT email, is_private FROM email_settings').all();

				const settingsData = settings
					.map(
						(s) => `
					<tr>
						<td>${s.email}</td>
						<td>${s.is_private ? 'Private (requires auth)' : 'Public'}</td>
					</tr>
				`
					)
					.join('');

				return new Response(settingsHtml.replace('{{SETTINGS_DATA}}', settingsData), {
					headers: { 'Content-Type': 'text/html' },
				});
			}

			// Handle email listing
			let query = 'SELECT from_org, to_addr, topic, code, created_at, message_id FROM code_mails ORDER BY created_at DESC';
			let params = [];

			if (path.length > 1) {
				const emailAddress = path.substring(1);

				// Check access permission
				const hasAccess = await checkEmailAccess(emailAddress, env, authHeader);
				if (!hasAccess) {
					return new Response('Unauthorized', {
						status: 401,
						headers: {
							'WWW-Authenticate': 'Basic realm="User Visible Realm"',
						},
					});
				}

				query = 'SELECT from_org, to_addr, topic, code, created_at, message_id FROM code_mails WHERE to_addr = ? ORDER BY created_at DESC';
				params = [emailAddress];
			} else {
				// Main page always requires auth
				if (!(await checkAuth(env, authHeader))) {
					return createUnauthorizedResponse();
				}
			}

			const { results } = await env.DB.prepare(query)
				.bind(...params)
				.all();

			let dataHtml = '';
			for (const row of results) {
				const codeLinkParts = row.code.split(',');
				let codeLinkContent;

				if (codeLinkParts.length > 1) {
					const [code, link] = codeLinkParts;
					codeLinkContent = `${code}<br><a href="${link}" target="_blank">${row.topic}</a>`;
				} else if (row.code.startsWith('http')) {
					codeLinkContent = `<a href="${row.code}" target="_blank">${row.topic}</a>`;
				} else {
					codeLinkContent = row.code;
				}

				dataHtml += `<tr>
                    <td>${row.from_org}</td>
                    <td>${row.to_addr}</td>
                    <td>${row.topic}</td>
                    <td>${codeLinkContent}</td>
                    <td>${row.created_at}</td>
                    <td><a href="/raw/${row.message_id}" target="_blank">View Raw</a></td>
                </tr>`;
			}

			let responseHtml = indexHtml
				.replace(
					'{{TABLE_HEADERS}}',
					`
                    <tr>
                        <th>From</th>
                        <th>To</th>
                        <th>Topic</th>
                        <th>Code/Link</th>
                        <th>Receive Time (GMT)</th>
                        <th>Raw Email</th>
                    </tr>
                `
				)
				.replace('{{DATA}}', dataHtml);

			// Add a new route handler for raw email viewing
			if (path.startsWith('/raw/')) {
				// 解码 message_id, 去掉 '/raw/' 前缀
				const messageId = decodeURIComponent(path.substring(5));

				if (!(await checkAuth(env, authHeader))) {
					return createUnauthorizedResponse();
				}

				const { results } = await env.DB.prepare('SELECT raw FROM raw_mails WHERE message_id = ?').bind(messageId).all();

				if (!results || results.length === 0) {
					return new Response('Email not found', { status: 404 });
				}

				const rawEmail = results[0].raw;
				const { text, html } = parseMultipartEmail(rawEmail);

				// Extract From and Subject from headers
				const fromMatch = rawEmail.match(/^From:(.+?)(?=\r?\n[^ \t])/ms);
				const subjectMatch = rawEmail.match(/^Subject:(.+?)(?=\r?\n[^ \t])/ms);

				const from = fromMatch ? fromMatch[1].trim() : 'Unknown Sender';
				const subject = subjectMatch ? subjectMatch[1].trim() : 'No Subject';

				// Use HTML content if available, otherwise fallback to text content
				let displayHtml = html || text.replace(/\n/g, '<br>');

				// If neither HTML nor text content was extracted, use the raw email
				if (!displayHtml) {
					const htmlMatch = rawEmail.match(/<html[\s\S]*?<\/html>/i);
					if (htmlMatch) {
						displayHtml = htmlMatch[0];
					} else {
						displayHtml = `<pre style="white-space: pre-wrap;">${rawEmail.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`;
					}
				}

				// Replace template placeholders
				const formattedHtml = rawEmailHtml
					.replace('{{RAW_EMAIL}}', rawEmail.replace(/</g, '&lt;').replace(/>/g, '&gt;'))
					.replace('{{HTML_CONTENT}}', displayHtml)
					.replace('{{FROM}}', from.replace(/</g, '&lt;').replace(/>/g, '&gt;'))
					.replace('{{SUBJECT}}', subject.replace(/</g, '&lt;').replace(/>/g, '&gt;'));

				return new Response(formattedHtml, {
					headers: { 'Content-Type': 'text/html' },
				});
			}

			return new Response(responseHtml, {
				headers: {
					'Content-Type': 'text/html',
				},
			});
		} catch (error) {
			console.error('Error:', error);
			return new Response('Internal Server Error', { status: 500 });
		}
	},

	// 主要功能
	async email(message, env, ctx) {
		const useBark = env.UseBark.toLowerCase() === 'true'; // true or false
		const GoogleAPIKey = env.GoogleAPIKey; // "xxxxxxxxxxxxxxxxxxxxxxxx"

		const rawEmail = await new Response(message.raw).text();
		const message_id = message.headers.get('Message-ID');

		// 将电子邮件保存到数据库
		const { success } = await env.DB.prepare(`INSERT INTO raw_mails (from_addr, to_addr, raw, message_id) VALUES (?, ?, ?, ?)`)
			.bind(
				message.from,
				message.to,
				rawEmail,
				message_id // 将电子邮件详细信息绑定到 SQL 语句
			)
			.run();

		// 检查电子邮件是否成功保存
		if (!success) {
			message.setReject(`Failed to save message from ${message.from} to ${message.to}`); // 如果保存失败，则拒绝消息
			console.log(`Failed to save message from ${message.from} to ${message.to}`); // 记录保存失败
		}

		// 调用AI，让AI抓取验证码，让AI返回`title`和`code`
		// title: 邮件是哪个公司/组织发来的验证码, 比如'Netflix'
		// code: 验证码/链接/密码，比如'123456'or'https://example.com/verify?code=123456',如都有则返回'code, link'
		// topic: 邮件主题，比如'line register verification'
		const aiPrompt = `
  Email content: ${rawEmail}.

  Please read the email and extract the following information:
  1. Code/Link/Password from the email (if available).
  2. Organization name (title) from which the email is sent.
  3. A brief summary of the email's topic (e.g., 'line register verification').

  Please provide the following information in JSON format:
  {
    "title": "The organization or company that sent the verification code (e.g., 'Netflix')",
    "code": "The extracted verification code, link, or password (e.g., '123456' or 'https://example.com/verify?code=123456')",
    "topic": "A brief summary of the email's topic (e.g., 'line register verification')",
    "codeExist": 1
  }


  If both a code and a link are present, include both in the 'code' field like this:
  "code": "code, link"

  If there is no code, clickable link, or this is an advertisement email, return:
  {
    "codeExist": 0
  }
`;

		try {
			// 添加重试机制
			const maxRetries = 3;
			let retryCount = 0;
			let extractedData = null;

			while (retryCount < maxRetries && !extractedData) {
				// 调用 Google AI API 来获取 title, code, topic
				const aiResponse = await fetch(
					`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${GoogleAPIKey}`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
						},
						body: JSON.stringify({
							contents: [
								{
									parts: [{ text: aiPrompt }],
								},
							],
						}),
					}
				);

				const aiData = await aiResponse.json();
				console.log(`AI response attempt ${retryCount + 1}:`, aiData);
				// 检测ai返回格式是否正确
				if (
					aiData &&
					aiData.candidates &&
					aiData.candidates[0] &&
					aiData.candidates[0].content &&
					aiData.candidates[0].content.parts &&
					aiData.candidates[0].content.parts[0]
				) {
					let extractedText = aiData.candidates[0].content.parts[0].text;
					console.log(`Extracted Text before parsing: "${extractedText}"`);

					// Use regex to extract JSON content from code blocks
					const jsonMatch = extractedText.match(/```json\s*([\s\S]*?)\s*```/);
					if (jsonMatch && jsonMatch[1]) {
						extractedText = jsonMatch[1].trim();
						console.log(`Extracted JSON Text: "${extractedText}"`);
					} else {
						// If no code block, assume the entire text is JSON
						extractedText = extractedText.trim();
						console.log(`Assuming entire text is JSON: "${extractedText}"`);
					}

					// Parse
					try {
						extractedData = JSON.parse(extractedText);
						console.log(`Parsed Extracted Data:`, extractedData);
					} catch (parseError) {
						console.error('JSON parsing error:', parseError);
						console.log(`Problematic JSON Text: "${extractedText}"`);
					}
				} else {
					console.error('AI response is missing expected data structure');
				}

				if (!extractedData) {
					retryCount++;
					if (retryCount < maxRetries) {
						console.log('Retrying AI request...');
					} else {
						console.error('Max retries reached. Unable to get valid AI response.');
					}
				}
			}

			// extract formatted data
			if (extractedData) {
				if (extractedData.codeExist === 1) {
					const title = extractedData.title || 'Unknown Organization';
					const code = extractedData.code || 'No Code Found';
					const topic = extractedData.topic || 'No Topic Found';

					// save extracted data to the database
					const { success: codeMailSuccess } = await env.DB.prepare(
						`INSERT INTO code_mails (from_addr, from_org, to_addr, code, topic, message_id) VALUES (?, ?, ?, ?, ?, ?)`
					)
						.bind(message.from, title, message.to, code, topic, message_id)
						.run();

					if (!codeMailSuccess) {
						message.setReject(`Failed to save extracted code for message from ${message.from} to ${message.to}`);
						console.log(`Failed to save extracted code for message from ${message.from} to ${message.to}`);
					}

					// Send title and code to Bark using GET request for each token
					if (useBark) {
						const barkUrl = env.barkUrl; // "https://api.day.app"
						// [token1, token2]
						const barkTokens = env.barkTokens
							.replace(/^\[|\]$/g, '')
							.split(',')
							.map((token) => token.trim());

						const barkUrlEncodedTitle = encodeURIComponent(title);
						const barkUrlEncodedCode = encodeURIComponent(code);

						for (const token of barkTokens) {
							const barkRequestUrl = `${barkUrl}/${token}/${barkUrlEncodedTitle}/${barkUrlEncodedCode}`;

							const barkResponse = await fetch(barkRequestUrl, {
								method: 'GET',
							});

							if (barkResponse.ok) {
								console.log(`Successfully sent notification to Bark for token ${token} for message from ${message.from} to ${message.to}`);
								const responseData = await barkResponse.json();
								console.log('Bark response:', responseData);
							} else {
								console.error(`Failed to send notification to Bark for token ${token}: ${barkResponse.status} ${barkResponse.statusText}`);
							}
						}
					}
				} else {
					console.log('No code found in this email, skipping Bark notification.');
				}
			} else {
				console.error('Failed to extract data from AI response after retries.');
			}
		} catch (e) {
			console.error('Error calling AI or saving to database:', e);
		}
	},
} satisfies ExportedHandler<Env>;
