const gameContainer = document.getElementById('game-container');
const player = document.getElementById('player');

const playerSpeed = 5; // 玩家移动速度
const bulletSpeed = 10; // 子弹速度

let playerX = gameContainer.offsetWidth / 2 - player.offsetWidth / 2;
let playerY = gameContainer.offsetHeight - player.offsetHeight - 20;

let keysPressed = {}; // 存储按下的键

// 初始化玩家位置
player.style.left = `${playerX}px`;
player.style.top = `${playerY}px`;

document.addEventListener('keydown', (e) => {
    keysPressed[e.key] = true;
});

document.addEventListener('keyup', (e) => {
    keysPressed[e.key] = false;
});

function handlePlayerMovement() {
    if (keysPressed['ArrowLeft'] || keysPressed['a']) {
        playerX -= playerSpeed;
    }
    if (keysPressed['ArrowRight'] || keysPressed['d']) {
        playerX += playerSpeed;
    }
    if (keysPressed['ArrowUp'] || keysPressed['w']) {
        playerY -= playerSpeed;
    }
    if (keysPressed['ArrowDown'] || keysPressed['s']) {
        playerY += playerSpeed;
    }

    // 限制玩家在游戏区域内
    playerX = Math.max(0, Math.min(playerX, gameContainer.offsetWidth - player.offsetWidth));
    playerY = Math.max(0, Math.min(playerY, gameContainer.offsetHeight - player.offsetHeight));

    player.style.left = `${playerX}px`;
    player.style.top = `${playerY}px`;
}

function createBullet() {
    const bullet = document.createElement('div');
    bullet.classList.add('bullet');
    bullet.style.left = `${playerX + player.offsetWidth / 2 - bullet.offsetWidth / 2}px`;
    bullet.style.top = `${playerY - bullet.offsetHeight}px`; // 从玩家上方发射
    gameContainer.appendChild(bullet);

    let bulletInterval = setInterval(() => {
        let bulletTop = parseInt(bullet.style.top) - bulletSpeed;
        bullet.style.top = `${bulletTop}px`;

        // 移除超出边界的子弹
        if (bulletTop < 0) {
            clearInterval(bulletInterval);
            bullet.remove();
        }
    }, 1000 / 60); // 每秒60帧
}

document.addEventListener('keypress', (e) => {
    if (e.key === ' ' || e.key === 'Spacebar') { // 按空格键发射子弹
        createBullet();
    }
});

// 游戏主循环
function gameLoop() {
    handlePlayerMovement();
    requestAnimationFrame(gameLoop);
}

gameLoop(); // 启动游戏
